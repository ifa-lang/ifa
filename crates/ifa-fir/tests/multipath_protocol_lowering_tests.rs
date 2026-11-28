use ifa_fir::{compile_to_fir, format_module, FirModule};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::{SourceMap, INTERNER};

fn compile_src_to_fir(src: &str) -> FirModule {
    let mut sm = SourceMap::new();
    let file_id = sm.add_file("test.ifa", src);
    let tokens = tokenize(file_id, src);
    let (program, parse_diags) = parse(file_id, tokens);
    assert!(parse_diags.is_empty(), "Parsing errors: {:?}", parse_diags);

    let analysis = analyze(&sm, &program);
    assert!(
        !analysis.has_errors(),
        "Semantic errors: {:?}",
        analysis.diagnostics
    );

    compile_to_fir(&program, &analysis.symbols, true, true).expect("FIR compilation failed")
}

#[test]
fn test_multipath_protocol_with_all_opt_passes() {
    let src = r#"
        @multipath(resilient)
        protocol StreamingEngine {
            slice ingress: Stream<u8>,
            slice egress: Stream<u8>,
        }

        fn stream_handler(x: u64) -> u64 {
            x + 42
        }
    "#;

    let mut sm = SourceMap::new();
    let file_id = sm.add_file("test_opt.ifa", src);
    let tokens = tokenize(file_id, src);
    let (program, diags) = parse(file_id, tokens);
    assert!(diags.is_empty());
    let analysis = analyze(&sm, &program);
    assert!(!analysis.has_errors());

    let module = ifa_fir::compile_to_fir_with_opts(
        &program,
        &analysis.symbols,
        true, // CoW
        true, // Gen
        true, // SROA
        true, // Vectorize
    )
    .expect("FIR compilation with all optimization passes failed");

    assert!(module
        .get_protocol(&INTERNER.intern("StreamingEngine"))
        .is_some());
    assert!(module
        .structs
        .iter()
        .any(|s| INTERNER.resolve(&s.name) == "__MultipathFlow_StreamingEngine"));
}

#[test]
fn test_multipath_protocol_and_slice_lowering() {
    let src = r#"
        @multipath(resilient)
        protocol MediaDistribution {
            slice control: Channel<u32>,
            slice audio: Stream<u8>,
            slice video: Stream<u8>,
        }

        fn dummy_entry() -> u64 {
            0
        }
    "#;

    let module = compile_src_to_fir(src);

    // 1. Verify Protocol Intermediate Representation
    let proto_sym = INTERNER.intern("MediaDistribution");
    let proto = module
        .get_protocol(&proto_sym)
        .expect("MediaDistribution protocol should be in FIR module");
    assert_eq!(proto.name, proto_sym);
    assert!(
        proto.is_multipath,
        "Protocol should be flagged as multipath"
    );
    assert_eq!(proto.channels.len(), 3);

    // Verify individual channels
    let ch_ctrl = proto
        .get_channel(&INTERNER.intern("control"))
        .expect("control channel missing");
    assert!(ch_ctrl.is_slice);
    assert!(ch_ctrl.is_multipath);
    assert!(ch_ctrl.fec_enabled);
    assert!(ch_ctrl.redundancy >= 2);

    let ch_audio = proto
        .get_channel(&INTERNER.intern("audio"))
        .expect("audio channel missing");
    assert!(ch_audio.is_slice);
    assert!(ch_audio.is_multipath);

    let ch_video = proto
        .get_channel(&INTERNER.intern("video"))
        .expect("video channel missing");
    assert!(ch_video.is_slice);
    assert!(ch_video.is_multipath);

    // 2. Verify Generated Flow Encapsulation Struct
    let flow_struct_name = proto.flow_encapsulation_struct;
    let flow_struct = module
        .structs
        .iter()
        .find(|s| s.name == flow_struct_name)
        .expect("Flow encapsulation struct missing in module structs");

    let field_names: Vec<String> = flow_struct
        .fields
        .iter()
        .map(|(sym, _)| INTERNER.resolve(sym))
        .collect();
    assert!(field_names.contains(&"flow_id".to_string()));
    assert!(field_names.contains(&"subpath_id".to_string()));
    assert!(field_names.contains(&"seq_num".to_string()));
    assert!(field_names.contains(&"flags".to_string()));
    assert!(field_names.contains(&"slice_tag".to_string()));
    assert!(field_names.contains(&"payload_len".to_string()));
    assert!(field_names.contains(&"control".to_string()));
    assert!(field_names.contains(&"audio".to_string()));
    assert!(field_names.contains(&"video".to_string()));

    // 3. Verify Generated Slice Descriptor Structs
    let desc_ctrl = module.structs.iter().find(|s| {
        INTERNER.resolve(&s.name) == "__MultipathSliceDescriptor_MediaDistribution_control"
    });
    assert!(
        desc_ctrl.is_some(),
        "Slice descriptor for control must be emitted"
    );

    let desc_audio = module.structs.iter().find(|s| {
        INTERNER.resolve(&s.name) == "__MultipathSliceDescriptor_MediaDistribution_audio"
    });
    assert!(
        desc_audio.is_some(),
        "Slice descriptor for audio must be emitted"
    );

    // 4. Verify Standard Subpath Metadata Struct
    let subpath_meta = module
        .structs
        .iter()
        .find(|s| INTERNER.resolve(&s.name) == "__MultipathSubpathMeta");
    assert!(
        subpath_meta.is_some(),
        "__MultipathSubpathMeta struct must be emitted"
    );

    // 5. Verify Printer output contains protocol
    let formatted = format_module(&module);
    assert!(formatted.contains("protocol @MediaDistribution @multipath"));
    assert!(formatted.contains("slice control:"));
    assert!(formatted.contains("@multipath(redundancy="));
}

#[test]
fn test_multipath_bicasting_protocol_attributes() {
    let src = r#"
        @multipath(bicasting)
        protocol TelemetryFeed {
            slice critical_event: Channel<u64>,
            heartbeat: Channel<u32>,
        }

        fn dummy_entry() -> u64 {
            1
        }
    "#;

    let module = compile_src_to_fir(src);
    let proto = module
        .get_protocol(&INTERNER.intern("TelemetryFeed"))
        .expect("TelemetryFeed protocol missing");
    assert!(proto.is_multipath);
    assert_eq!(proto.channels.len(), 2);

    let critical = proto
        .get_channel(&INTERNER.intern("critical_event"))
        .unwrap();
    assert!(critical.is_slice);
    assert_eq!(critical.redundancy, 2);
    assert!(critical
        .subpath_tags
        .iter()
        .any(|t| INTERNER.resolve(t) == "primary"));
    assert!(critical
        .subpath_tags
        .iter()
        .any(|t| INTERNER.resolve(t) == "secondary"));
}

#[test]
fn test_struct_traffic_slice_lowering() {
    let src = r#"
        struct PipeTunnel {
            tunnel_id: u64,
            @multipath(pacing)
            slice data_pipe: Channel<u8>,
        }

        fn dummy_entry() -> u64 {
            2
        }
    "#;

    let module = compile_src_to_fir(src);

    // Verify struct lowered
    let st = module
        .structs
        .iter()
        .find(|s| INTERNER.resolve(&s.name) == "PipeTunnel")
        .expect("PipeTunnel struct missing");
    assert_eq!(st.fields.len(), 2);

    // Verify slice descriptor emitted for struct field
    let slice_desc = module
        .structs
        .iter()
        .find(|s| INTERNER.resolve(&s.name) == "__MultipathSliceDescriptor_PipeTunnel_data_pipe");
    assert!(
        slice_desc.is_some(),
        "Slice descriptor for PipeTunnel::data_pipe must be emitted"
    );

    // Verify Subpath Meta present
    let subpath_meta = module
        .structs
        .iter()
        .find(|s| INTERNER.resolve(&s.name) == "__MultipathSubpathMeta");
    assert!(
        subpath_meta.is_some(),
        "__MultipathSubpathMeta must be emitted for struct slices"
    );
}

#[test]
fn test_protocol_deterministic_sorting() {
    let src = r#"
        protocol BetaProto {
            ch1: Channel<u32>,
        }

        protocol AlphaProto {
            ch2: Channel<u32>,
        }

        fn dummy_entry() -> u64 {
            3
        }
    "#;

    let module = compile_src_to_fir(src);
    assert_eq!(module.protocols.len(), 2);
    assert_eq!(INTERNER.resolve(&module.protocols[0].name), "AlphaProto");
    assert_eq!(INTERNER.resolve(&module.protocols[1].name), "BetaProto");
}
