use ifa_ast::ParamMode;
use ifa_fir::{
    compile_to_fir, ArenaFusionPass, FirFunction, FirInterpreter, FirModule, FirParam, FirStruct,
    FirType, FirValue, GenerationalOptPass, Instruction, Terminator, ValueExpr, ValueId,
};
use ifa_sema::types::IntType;
use ifa_span::{Span, INTERNER};

#[test]
fn test_binary_tree_arena_merging() {
    let src = r#"
        struct TreeNode {
            val: i64,
            left: ?ref TreeNode,
            right: ?ref TreeNode,
        }

        pub fn test_marker() -> i64 {
            return 42;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("tree_arena.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    // Create a tree builder function directly in FIR with 3 GenAlloc instructions
    let tree_type = FirType::Struct(
        INTERNER.intern("TreeNode"),
        vec![
            (INTERNER.intern("val"), FirType::Int(IntType::I64)),
            (
                INTERNER.intern("left"),
                FirType::Optional(Box::new(FirType::GenerationalRef(Box::new(
                    FirType::Struct(INTERNER.intern("TreeNode"), Vec::new()),
                )))),
            ),
            (
                INTERNER.intern("right"),
                FirType::Optional(Box::new(FirType::GenerationalRef(Box::new(
                    FirType::Struct(INTERNER.intern("TreeNode"), Vec::new()),
                )))),
            ),
        ],
    );

    let mut builder_fn = FirFunction::new(
        INTERNER.intern("build_tree"),
        Vec::new(),
        FirType::GenerationalRef(Box::new(tree_type.clone())),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let entry_b = builder_fn.entry_block;
    let v_left = builder_fn.alloc_value();
    let v_right = builder_fn.alloc_value();
    let v_root = builder_fn.alloc_value();

    let bb = builder_fn.get_block_mut(entry_b).unwrap();
    // 3 allocations with no arena specified (None)
    bb.push_instruction(Instruction::new(
        Some(v_left),
        ValueExpr::GenAlloc {
            ty: tree_type.clone(),
            arena: None,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_right),
        ValueExpr::GenAlloc {
            ty: tree_type.clone(),
            arena: None,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_root),
        ValueExpr::GenAlloc {
            ty: tree_type.clone(),
            arena: None,
        },
        Span::DUMMY,
    ));

    // Connect them: root.left = v_left, root.right = v_right
    bb.push_instruction(Instruction::new(
        None,
        ValueExpr::SetField {
            base: v_root,
            field_idx: 1,
            val: v_left,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        None,
        ValueExpr::SetField {
            base: v_root,
            field_idx: 2,
            val: v_right,
        },
        Span::DUMMY,
    ));
    bb.set_terminator(Terminator::Return(Some(v_root)));

    module.functions.push(builder_fn);

    let mut arena_pass = ArenaFusionPass::new();
    let stats = arena_pass.run_on_module(&mut module);

    assert!(
        stats.recursive_structs_analyzed >= 1,
        "Expected at least 1 recursive struct analyzed, got {}",
        stats.recursive_structs_analyzed
    );
    assert_eq!(
        stats.allocations_fused, 3,
        "All 3 tree node allocations must be fused into unified arena"
    );

    // Verify all 3 allocations now share the exact same synthetic arena ID
    let f = module
        .functions
        .iter()
        .find(|f| f.name == INTERNER.intern("build_tree"))
        .unwrap();
    let mut arena_ids = Vec::new();
    for inst in &f.blocks[0].instructions {
        if let ValueExpr::GenAlloc { arena, .. } = &inst.expr {
            arena_ids.push(*arena);
        }
    }

    assert_eq!(arena_ids.len(), 3);
    assert!(arena_ids[0].is_some(), "Arena ID must be assigned");
    assert_eq!(arena_ids[0], arena_ids[1]);
    assert_eq!(arena_ids[1], arena_ids[2]);
}

#[test]
fn test_immutable_tree_recursive_access_barrier_elimination() {
    let src = r#"
        struct BinaryNode {
            value: i64,
            left: ?ref BinaryNode,
            right: ?ref BinaryNode,
        }

        pub fn sum_children(n: ref BinaryNode) -> i64 {
            let l = n.left;
            let r = n.right;
            return 10;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("tree_barriers.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();

    let mut arena_pass = ArenaFusionPass::new();
    let stats = arena_pass.run_on_module(&mut module);

    assert!(
        stats.recursive_structs_analyzed >= 1,
        "Recursive struct must be analyzed"
    );
    assert_eq!(
        stats.access_barriers_eliminated, 1,
        "Subsequent access barrier must be eliminated by ArenaFusionPass"
    );

    // Verify the function has exactly 1 eliminated check
    let func = &module.functions[0];
    let redundant_count = func.blocks[0]
        .instructions
        .iter()
        .filter(|inst| {
            matches!(
                inst.expr,
                ValueExpr::GenCheck {
                    redundant: true,
                    ..
                }
            )
        })
        .count();
    assert_eq!(redundant_count, 1);
}

#[test]
fn test_deep_recursive_chain_access_barrier_elimination() {
    let node_ty = FirType::Struct(
        INTERNER.intern("ChainNode"),
        vec![
            (INTERNER.intern("val"), FirType::Int(IntType::I64)),
            (
                INTERNER.intern("next"),
                FirType::GenerationalRef(Box::new(FirType::Struct(
                    INTERNER.intern("ChainNode"),
                    Vec::new(),
                ))),
            ),
        ],
    );

    let mut chain_fn = FirFunction::new(
        INTERNER.intern("traverse_chain"),
        vec![FirParam {
            name: INTERNER.intern("root"),
            val: ValueId(0),
            ty: FirType::GenerationalRef(Box::new(node_ty.clone())),
            mode: ParamMode::In,
        }],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b0 = chain_fn.entry_block;
    let v_deref0 = chain_fn.alloc_value();
    let v_child1 = chain_fn.alloc_value();
    let v_deref1 = chain_fn.alloc_value();
    let v_child2 = chain_fn.alloc_value();
    let v_deref2 = chain_fn.alloc_value();
    let v_val = chain_fn.alloc_value();

    let bb = chain_fn.get_block_mut(b0).unwrap();

    // 1. Initial barrier on root node
    bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(0),
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_deref0),
        ValueExpr::GenDeref {
            ref_val: ValueId(0),
        },
        Span::DUMMY,
    ));

    // 2. Child projection: node.next
    bb.push_instruction(Instruction::new(
        Some(v_child1),
        ValueExpr::GetField {
            base: v_deref0,
            field_idx: 1,
            field_name: INTERNER.intern("next"),
        },
        Span::DUMMY,
    ));

    // 3. Access barrier on child1 (should be ELIMINATED)
    bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_child1,
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_deref1),
        ValueExpr::GenDeref { ref_val: v_child1 },
        Span::DUMMY,
    ));

    // 4. Grandchild projection: child1.next
    bb.push_instruction(Instruction::new(
        Some(v_child2),
        ValueExpr::GetField {
            base: v_deref1,
            field_idx: 1,
            field_name: INTERNER.intern("next"),
        },
        Span::DUMMY,
    ));

    // 5. Access barrier on grandchild (should be ELIMINATED)
    bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_child2,
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_deref2),
        ValueExpr::GenDeref { ref_val: v_child2 },
        Span::DUMMY,
    ));

    bb.push_instruction(Instruction::new(
        Some(v_val),
        ValueExpr::GetField {
            base: v_deref2,
            field_idx: 0,
            field_name: INTERNER.intern("val"),
        },
        Span::DUMMY,
    ));
    bb.set_terminator(Terminator::Return(Some(v_val)));

    let mut module = ifa_fir::FirModule {
        name: INTERNER.intern("test_chain_mod"),
        structs: vec![ifa_fir::FirStruct {
            name: INTERNER.intern("ChainNode"),
            fields: vec![
                (INTERNER.intern("val"), FirType::Int(IntType::I64)),
                (
                    INTERNER.intern("next"),
                    FirType::GenerationalRef(Box::new(node_ty.clone())),
                ),
            ],
            is_pub: true,
            span: Span::DUMMY,
        }],
        enums: Vec::new(),
        constants: Vec::new(),
        functions: vec![chain_fn],
    };

    let mut arena_pass = ArenaFusionPass::new();
    let stats = arena_pass.run_on_module(&mut module);

    println!(
        "FIR FUNCTION:\n{}",
        ifa_fir::printer::format_function(&module.functions[0])
    );
    println!("ARENA STATS: {:?}", stats);

    assert!(
        stats.access_barriers_eliminated >= 2,
        "Both internal access barriers must be eliminated, got {}",
        stats.access_barriers_eliminated
    );

    // Verify instructions in the function
    let f = &module.functions[0];
    let redundant_count = f.blocks[0]
        .instructions
        .iter()
        .filter(|inst| {
            matches!(
                inst.expr,
                ValueExpr::GenCheck {
                    redundant: true,
                    ..
                }
            )
        })
        .count();

    assert_eq!(
        redundant_count, 2,
        "Exactly 2 access barriers must be marked redundant"
    );

    let stripped = GenerationalOptPass::strip_redundant_checks(&mut module.functions[0]);
    assert_eq!(stripped, 2, "Both redundant checks stripped");
}

#[test]
fn test_disjoint_arenas_reconciliation() {
    let node_ty = FirType::Struct(
        INTERNER.intern("DagNode"),
        vec![
            (INTERNER.intern("val"), FirType::Int(IntType::I64)),
            (
                INTERNER.intern("edge"),
                FirType::GenerationalRef(Box::new(FirType::Struct(
                    INTERNER.intern("DagNode"),
                    Vec::new(),
                ))),
            ),
        ],
    );

    let mut f = FirFunction::new(
        INTERNER.intern("connect_dags"),
        Vec::new(),
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b0 = f.entry_block;
    let v_a = f.alloc_value();
    let v_b = f.alloc_value();

    let bb = f.get_block_mut(b0).unwrap();
    // Allocation A on arena 10, allocation B on arena 20
    bb.push_instruction(Instruction::new(
        Some(v_a),
        ValueExpr::GenAlloc {
            ty: node_ty.clone(),
            arena: Some(10),
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_b),
        ValueExpr::GenAlloc {
            ty: node_ty.clone(),
            arena: Some(20),
        },
        Span::DUMMY,
    ));
    // Connect them: a.edge = b
    bb.push_instruction(Instruction::new(
        None,
        ValueExpr::SetField {
            base: v_a,
            field_idx: 1,
            val: v_b,
        },
        Span::DUMMY,
    ));
    bb.set_terminator(Terminator::Return(None));

    let mut module = ifa_fir::FirModule {
        name: INTERNER.intern("test_dag_mod"),
        structs: vec![ifa_fir::FirStruct {
            name: INTERNER.intern("DagNode"),
            fields: vec![
                (INTERNER.intern("val"), FirType::Int(IntType::I64)),
                (
                    INTERNER.intern("edge"),
                    FirType::GenerationalRef(Box::new(node_ty.clone())),
                ),
            ],
            is_pub: true,
            span: Span::DUMMY,
        }],
        enums: Vec::new(),
        constants: Vec::new(),
        functions: vec![f],
    };

    let mut pass = ArenaFusionPass::new();
    let stats = pass.run_on_module(&mut module);

    assert_eq!(
        stats.arenas_merged, 1,
        "Distinct arenas 10 and 20 must be reconciled"
    );
    assert_eq!(
        stats.allocations_fused, 2,
        "Both allocations fused into unified arena"
    );

    // Check that both GenAllocs now share arena 10 (the min)
    let func = &module.functions[0];
    for inst in &func.blocks[0].instructions {
        if let ValueExpr::GenAlloc { arena, .. } = &inst.expr {
            assert_eq!(
                *arena,
                Some(10),
                "Both allocations must use unified arena 10"
            );
        }
    }
}

#[test]
fn test_interpreter_execution_fidelity_with_fused_arenas() {
    let src = r#"
        struct Leaf {
            num: i64,
        }

        pub fn compute_leaf_val() -> i64 {
            let l = Leaf(num: 123);
            let r = ref l;
            return r.num + r.num;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("leaf_calc.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("compute_leaf_val", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(246));
}

#[test]
fn test_recursive_interprocedural_tree_traversal() {
    let src = r#"
        struct IntNode {
            val: i64,
        }

        impl IntNode {
            pub fn read_doubled(n: ref IntNode) -> i64 {
                let v = n.val;
                return v * 2;
            }
        }

        pub fn run_traversal() -> i64 {
            let n = IntNode(val: 25);
            let r = ref n;
            let first = r.read_doubled();
            let second = r.read_doubled();
            return first + second;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("recursive_tree.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("run_traversal", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(100));
}

#[test]
fn test_zero_copy_streaming_pipeline_arena_coalescing() {
    let src = r#"
        struct StreamChunk {
            payload_len: i64,
            capacity: i64,
        }

        struct StreamPacket {
            chunk: ?ref StreamChunk,
            seq_num: i64,
        }

        pub fn test_pipeline_marker() -> i64 {
            return 0;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("stream_pipeline.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let chunk_ty = FirType::Struct(
        INTERNER.intern("StreamChunk"),
        vec![
            (INTERNER.intern("payload_len"), FirType::Int(IntType::I64)),
            (INTERNER.intern("capacity"), FirType::Int(IntType::I64)),
        ],
    );

    let packet_ty = FirType::Struct(
        INTERNER.intern("StreamPacket"),
        vec![
            (
                INTERNER.intern("chunk"),
                FirType::Optional(Box::new(FirType::GenerationalRef(Box::new(
                    chunk_ty.clone(),
                )))),
            ),
            (INTERNER.intern("seq_num"), FirType::Int(IntType::I64)),
        ],
    );

    let mut stream_pipeline_fn = FirFunction::new(
        INTERNER.intern("run_stream_stage"),
        Vec::new(),
        FirType::GenerationalRef(Box::new(packet_ty.clone())),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let entry = stream_pipeline_fn.entry_block;
    let v_chunk1 = stream_pipeline_fn.alloc_value();
    let v_chunk2 = stream_pipeline_fn.alloc_value();
    let v_packet = stream_pipeline_fn.alloc_value();

    let bb = stream_pipeline_fn.get_block_mut(entry).unwrap();
    // Allocate 2 chunks and 1 packet in the pipeline
    bb.push_instruction(Instruction::new(
        Some(v_chunk1),
        ValueExpr::GenAlloc {
            ty: chunk_ty.clone(),
            arena: None,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_chunk2),
        ValueExpr::GenAlloc {
            ty: chunk_ty.clone(),
            arena: None,
        },
        Span::DUMMY,
    ));
    bb.push_instruction(Instruction::new(
        Some(v_packet),
        ValueExpr::GenAlloc {
            ty: packet_ty.clone(),
            arena: None,
        },
        Span::DUMMY,
    ));

    // Connect chunk1 to packet
    bb.push_instruction(Instruction::new(
        None,
        ValueExpr::SetField {
            base: v_packet,
            field_idx: 0,
            val: v_chunk1,
        },
        Span::DUMMY,
    ));

    bb.set_terminator(Terminator::Return(Some(v_packet)));
    module.functions.push(stream_pipeline_fn);

    let mut pass = ArenaFusionPass::new();
    let stats = pass.run_on_module(&mut module);

    assert!(
        stats.allocations_fused >= 3,
        "Expected at least 3 allocations fused in the streaming pipeline, got: {}",
        stats.allocations_fused
    );
    assert!(
        stats.streaming_arenas_fused >= 1,
        "Expected at least 1 streaming arena fused, got: {}",
        stats.streaming_arenas_fused
    );
    assert!(
        stats.zero_copy_pipelines_optimized >= 1,
        "Expected zero-copy pipeline optimized count >= 1, got: {}",
        stats.zero_copy_pipelines_optimized
    );

    // Verify all allocations share the exact same synthetic arena
    let optimized_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "run_stream_stage")
        .unwrap();

    let mut assigned_arenas = Vec::new();
    for inst in &optimized_fn.get_block(entry).unwrap().instructions {
        if let ValueExpr::GenAlloc { arena, .. } = &inst.expr {
            assigned_arenas.push(*arena);
        }
    }

    assert_eq!(assigned_arenas.len(), 3);
    assert!(assigned_arenas[0].is_some(), "Arena ID must be assigned");
    assert_eq!(
        assigned_arenas[0], assigned_arenas[1],
        "All streaming allocations must share unified arena"
    );
    assert_eq!(
        assigned_arenas[1], assigned_arenas[2],
        "All streaming allocations must share unified arena"
    );
}

#[test]
fn test_interprocedural_nested_streaming_pipeline_arena_fusion() {
    let chunk_ty = FirType::Struct(
        INTERNER.intern("StreamChunk"),
        vec![
            (INTERNER.intern("len"), FirType::Int(IntType::I64)),
            (INTERNER.intern("cap"), FirType::Int(IntType::I64)),
        ],
    );

    let packet_ty = FirType::Struct(
        INTERNER.intern("StreamPacket"),
        vec![
            (
                INTERNER.intern("chunk"),
                FirType::GenerationalRef(Box::new(chunk_ty.clone())),
            ),
            (INTERNER.intern("id"), FirType::Int(IntType::I64)),
        ],
    );

    // Stage 1: produce_chunk() -> allocates chunk with arena 42
    let mut f_produce = FirFunction::new(
        INTERNER.intern("produce_chunk"),
        Vec::new(),
        FirType::GenerationalRef(Box::new(chunk_ty.clone())),
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    let e1 = f_produce.entry_block;
    let v_chunk = f_produce.alloc_value();
    let bb1 = f_produce.get_block_mut(e1).unwrap();
    bb1.push_instruction(Instruction::new(
        Some(v_chunk),
        ValueExpr::GenAlloc {
            ty: chunk_ty.clone(),
            arena: Some(42),
        },
        Span::DUMMY,
    ));
    bb1.set_terminator(Terminator::Return(Some(v_chunk)));

    // Stage 2: wrap_packet(c: ref StreamChunk) -> allocates StreamPacket with arena None, and sets packet.chunk = c
    let mut f_wrap = FirFunction::new(
        INTERNER.intern("wrap_packet"),
        Vec::new(),
        FirType::GenerationalRef(Box::new(packet_ty.clone())),
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    let p_c = f_wrap.alloc_value();
    f_wrap.params.push(FirParam {
        name: INTERNER.intern("c"),
        ty: FirType::GenerationalRef(Box::new(chunk_ty.clone())),
        val: p_c,
        mode: ParamMode::In,
    });
    let e2 = f_wrap.entry_block;
    let v_pkt = f_wrap.alloc_value();
    let bb2 = f_wrap.get_block_mut(e2).unwrap();
    bb2.push_instruction(Instruction::new(
        Some(v_pkt),
        ValueExpr::GenAlloc {
            ty: packet_ty.clone(),
            arena: None,
        },
        Span::DUMMY,
    ));
    bb2.push_instruction(Instruction::new(
        None,
        ValueExpr::SetField {
            base: v_pkt,
            field_idx: 0,
            val: p_c,
        },
        Span::DUMMY,
    ));
    bb2.set_terminator(Terminator::Return(Some(v_pkt)));

    // Pipeline driver: main_pipeline() calls produce_chunk(), then calls wrap_packet(chunk)
    let mut f_driver = FirFunction::new(
        INTERNER.intern("main_pipeline"),
        Vec::new(),
        FirType::GenerationalRef(Box::new(packet_ty.clone())),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let e3 = f_driver.entry_block;
    let v_c = f_driver.alloc_value();
    let v_p = f_driver.alloc_value();
    let bb3 = f_driver.get_block_mut(e3).unwrap();
    bb3.push_instruction(Instruction::new(
        Some(v_c),
        ValueExpr::CallDirect {
            name: INTERNER.intern("produce_chunk"),
            args: Vec::new(),
        },
        Span::DUMMY,
    ));
    bb3.push_instruction(Instruction::new(
        Some(v_p),
        ValueExpr::CallDirect {
            name: INTERNER.intern("wrap_packet"),
            args: vec![v_c],
        },
        Span::DUMMY,
    ));
    bb3.set_terminator(Terminator::Return(Some(v_p)));

    let mut module = FirModule {
        name: INTERNER.intern("streaming_pipeline_mod"),
        structs: vec![
            FirStruct {
                name: INTERNER.intern("StreamChunk"),
                fields: vec![
                    (INTERNER.intern("len"), FirType::Int(IntType::I64)),
                    (INTERNER.intern("cap"), FirType::Int(IntType::I64)),
                ],
                is_pub: true,
                span: Span::DUMMY,
            },
            FirStruct {
                name: INTERNER.intern("StreamPacket"),
                fields: vec![
                    (
                        INTERNER.intern("chunk"),
                        FirType::GenerationalRef(Box::new(chunk_ty.clone())),
                    ),
                    (INTERNER.intern("id"), FirType::Int(IntType::I64)),
                ],
                is_pub: true,
                span: Span::DUMMY,
            },
        ],
        enums: Vec::new(),
        constants: Vec::new(),
        functions: vec![f_produce, f_wrap, f_driver],
    };

    let mut pass = ArenaFusionPass::new();
    let stats = pass.run_on_module(&mut module);

    assert!(
        stats.interprocedural_fusions >= 1,
        "Interprocedural arena fusion must occur across call boundaries: {:?}",
        stats
    );

    // Verify wrap_packet's GenAlloc was rewritten to arena 42!
    let wrap_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "wrap_packet")
        .unwrap();

    let mut wrap_arena = None;
    for inst in &wrap_fn.blocks[0].instructions {
        if let ValueExpr::GenAlloc { arena, .. } = inst.expr {
            wrap_arena = arena;
        }
    }

    assert_eq!(
        wrap_arena,
        Some(42),
        "wrap_packet must adopt caller's incoming chunk arena 42"
    );
}

#[test]
fn test_interprocedural_streaming_access_barrier_elimination() {
    let chunk_ty = FirType::Struct(
        INTERNER.intern("StreamBuffer"),
        vec![(INTERNER.intern("size"), FirType::Int(IntType::I64))],
    );

    // consume(b: ref StreamBuffer) -> accesses b.size with GenCheck
    let mut f_consume = FirFunction::new(
        INTERNER.intern("consume_buffer"),
        Vec::new(),
        FirType::Int(IntType::I64),
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    let p_b = f_consume.alloc_value();
    f_consume.params.push(FirParam {
        name: INTERNER.intern("b"),
        ty: FirType::GenerationalRef(Box::new(chunk_ty.clone())),
        val: p_b,
        mode: ParamMode::In,
    });
    let e1 = f_consume.entry_block;
    let v_field = f_consume.alloc_value();
    let bb1 = f_consume.get_block_mut(e1).unwrap();
    // GenCheck on parameter b
    bb1.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: p_b,
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb1.push_instruction(Instruction::new(
        Some(v_field),
        ValueExpr::GetField {
            base: p_b,
            field_idx: 0,
            field_name: INTERNER.intern("size"),
        },
        Span::DUMMY,
    ));
    bb1.set_terminator(Terminator::Return(Some(v_field)));

    // caller: allocates StreamBuffer in arena 5, so it is safe, then calls consume_buffer
    let mut f_caller = FirFunction::new(
        INTERNER.intern("caller_pipeline"),
        Vec::new(),
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let e2 = f_caller.entry_block;
    let v_buf = f_caller.alloc_value();
    let v_res = f_caller.alloc_value();
    let bb2 = f_caller.get_block_mut(e2).unwrap();
    bb2.push_instruction(Instruction::new(
        Some(v_buf),
        ValueExpr::GenAlloc {
            ty: chunk_ty.clone(),
            arena: Some(5),
        },
        Span::DUMMY,
    ));
    bb2.push_instruction(Instruction::new(
        Some(v_res),
        ValueExpr::CallDirect {
            name: INTERNER.intern("consume_buffer"),
            args: vec![v_buf],
        },
        Span::DUMMY,
    ));
    bb2.set_terminator(Terminator::Return(Some(v_res)));

    let mut module = FirModule {
        name: INTERNER.intern("test_barrier_mod"),
        structs: vec![FirStruct {
            name: INTERNER.intern("StreamBuffer"),
            fields: vec![(INTERNER.intern("size"), FirType::Int(IntType::I64))],
            is_pub: true,
            span: Span::DUMMY,
        }],
        enums: Vec::new(),
        constants: Vec::new(),
        functions: vec![f_consume, f_caller],
    };

    let mut pass = ArenaFusionPass::new();
    let stats = pass.run_on_module(&mut module);

    assert!(
        stats.interprocedural_barriers_eliminated >= 1,
        "Interprocedural access barrier on verified parameter must be eliminated: {:?}",
        stats
    );

    let consume_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "consume_buffer")
        .unwrap();

    let check_redundant = consume_fn.blocks[0].instructions.iter().any(|inst| {
        matches!(
            inst.expr,
            ValueExpr::GenCheck {
                redundant: true,
                ..
            }
        )
    });

    assert!(
        check_redundant,
        "consume_buffer's GenCheck must be marked redundant across call boundary"
    );
}
