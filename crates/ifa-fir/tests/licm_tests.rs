use ifa_fir::printer::format_function;
use ifa_fir::{compile_to_fir, lower_program, FirInterpreter, FirValue, LicmPass};

#[test]
fn test_nested_generic_struct_field_projection_licm_hoisting() {
    let src = r#"
        struct Inner<T> {
            val: T,
        }

        struct Pair<T> {
            first: Inner<T>,
            second: Inner<T>,
        }

        pub fn sum_loop(p: Pair<i64>, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + p.first.val;
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_nested.ifa", src);
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
    let func = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "sum_loop")
        .expect("sum_loop must exist");

    let _formatted = format_function(func);

    // In sum_loop, the preheader block (bb1) must contain the hoisted field projections
    let mut interp = FirInterpreter::new(&module);
    let inner_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Inner__i64"),
        fields: vec![FirValue::Int(15)],
    };
    let pair_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Pair__Inner__i64"),
        fields: vec![inner_obj.clone(), inner_obj],
    };

    // 15 * 10 = 150
    let res = interp
        .execute_function("sum_loop", vec![pair_obj, FirValue::Int(10)])
        .unwrap();
    assert_eq!(res, FirValue::Int(150));
}

#[test]
fn test_licm_preserves_semantics_with_multiple_nested_generic_fields() {
    let src = r#"
        struct Config<T> {
            multiplier: T,
            offset: T,
        }

        pub fn compute_scaled(cfg: Config<i64>, limit: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < limit {
                acc = acc + (cfg.multiplier + cfg.offset);
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_multi.ifa", src);
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
    let cfg_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Config__i64"),
        fields: vec![FirValue::Int(7), FirValue::Int(3)],
    };

    // (7 + 3) * 5 = 50
    let res = interp
        .execute_function("compute_scaled", vec![cfg_obj, FirValue::Int(5)])
        .unwrap();
    assert_eq!(res, FirValue::Int(50));
}

#[test]
fn test_licm_pass_stats_and_hoisting_action() {
    let src = r#"
        struct Data<T> {
            val: T,
        }

        pub fn run_hoisting_action(d: Data<i64>, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + d.val;
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_action.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    println!("BEFORE LICM:\n{}", format_function(&module.functions[0]));
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);
    println!("AFTER LICM:\n{}", format_function(&module.functions[0]));
    println!("STATS: {:?}", licm.stats());

    let stats = licm.stats();
    assert!(
        stats.loops_optimized >= 1,
        "LICM must optimize at least one loop with generic struct field access"
    );

    let mut interp = FirInterpreter::new(&module);
    let data_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Data__i64"),
        fields: vec![FirValue::Int(100)],
    };
    let res = interp
        .execute_function("run_hoisting_action", vec![data_obj, FirValue::Int(4)])
        .unwrap();
    assert_eq!(res, FirValue::Int(400));
}

#[test]
fn test_licm_bounds_check_hoisting_out_of_loop() {
    let src = r#"
        pub fn sum_array_licm(arr: [i64; 4], idx: i64, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + arr[idx];
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_bce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.hoisted_bounds_checks >= 1,
        "Expected at least 1 hoisted bounds check, got {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let arr_val = FirValue::Array(vec![
        FirValue::Int(10),
        FirValue::Int(25),
        FirValue::Int(30),
        FirValue::Int(45),
    ]);

    // arr[1] = 25; 25 * 4 = 100
    let res = interp
        .execute_function(
            "sum_array_licm",
            vec![arr_val, FirValue::Int(1), FirValue::Int(4)],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(100));
}

#[test]
fn test_licm_nested_struct_disjoint_field_write_fusion() {
    let src = r#"
        struct ValueHolder {
            num: i64,
        }

        struct DualContext {
            read_side: ValueHolder,
            write_side: ValueHolder,
        }

        pub fn process_context(ctx: DualContext, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            mut written = ctx.write_side.num;
            while i < n {
                acc = acc + ctx.read_side.num;
                written = written + 1;
                i = i + 1;
            }
            return acc + written;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_disjoint.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.loops_optimized >= 1,
        "Expected loop to be optimized by LICM with disjoint field analysis"
    );

    let mut interp = FirInterpreter::new(&module);
    let read_holder = FirValue::Struct {
        name: ifa_span::INTERNER.intern("ValueHolder"),
        fields: vec![FirValue::Int(50)],
    };
    let write_holder = FirValue::Struct {
        name: ifa_span::INTERNER.intern("ValueHolder"),
        fields: vec![FirValue::Int(5)],
    };
    let dual_ctx = FirValue::Struct {
        name: ifa_span::INTERNER.intern("DualContext"),
        fields: vec![read_holder, write_holder],
    };

    // acc = 50 * 3 = 150; written = 5 + 3 = 8; total = 158
    let res = interp
        .execute_function("process_context", vec![dual_ctx, FirValue::Int(3)])
        .unwrap();
    assert_eq!(res, FirValue::Int(158));
}

#[test]
fn test_licm_nested_struct_array_bounds_check_hoisting() {
    let src = r#"
        struct BufferWrapper {
            items: [i64; 4],
        }

        struct SystemState {
            buf: BufferWrapper,
            step: i64,
        }

        pub fn run_state_loop(s: SystemState, idx: i64, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + s.buf.items[idx];
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_nested_bce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.hoisted_bounds_checks >= 1,
        "Expected nested struct array bounds check to be hoisted, got {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let buf_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("BufferWrapper"),
        fields: vec![FirValue::Array(vec![
            FirValue::Int(11),
            FirValue::Int(22),
            FirValue::Int(33),
            FirValue::Int(44),
        ])],
    };
    let state_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("SystemState"),
        fields: vec![buf_obj, FirValue::Int(1)],
    };

    // items[2] = 33; 33 * 5 = 165
    let res = interp
        .execute_function(
            "run_state_loop",
            vec![state_obj, FirValue::Int(2), FirValue::Int(5)],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(165));
}

#[test]
fn test_licm_hoists_alloca_and_gen_ref_cascade() {
    use ifa_ast::ParamMode;
    use ifa_fir::ir::*;
    use ifa_fir::types::FirType;
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("hoist_alloc_gen_loop");
    let param = FirParam {
        name: INTERNER.intern("base_ptr"),
        val: ValueId(0),
        ty: FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: false,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![param],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    // b0: entry
    let b_entry = BlockId(0);
    let b_preheader = func.alloc_block(); // b1
    let b_header = func.alloc_block(); // b2
    let b_body = func.alloc_block(); // b3
    let b_exit = func.alloc_block(); // b4

    func.get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_preheader,
            args: Vec::new(),
        });

    func.get_block_mut(b_preheader)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_header,
            args: Vec::new(),
        });

    let v_cond = func.alloc_value();
    func.get_block_mut(b_header)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    // Body contains:
    // 1. Alloca (no uses, stack allocation)
    let v_alloca = func.alloc_value();
    // 2. GenRef referencing parameter base_ptr ValueId(0)
    let v_gen_ref = func.alloc_value();
    // 3. GenDeref of v_gen_ref
    let v_deref = func.alloc_value();
    // 4. Invariant Load of v_deref
    let v_load = func.alloc_value();

    let body_bb = func.get_block_mut(b_body).unwrap();
    body_bb.push_instruction(Instruction::new(
        Some(v_alloca),
        ValueExpr::Alloca {
            ty: FirType::Int(IntType::I64),
            name: None,
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(v_gen_ref),
        ValueExpr::GenRef { ptr: ValueId(0) },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(v_deref),
        ValueExpr::GenDeref { ref_val: v_gen_ref },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(v_load),
        ValueExpr::Load { ptr: v_deref },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    func.get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(Some(v_load)));

    let mut licm = LicmPass::new();
    licm.run_on_function(&mut func);

    let stats = licm.stats();
    assert_eq!(
        stats.hoisted_allocs, 1,
        "Expected 1 hoisted alloca: {:?}",
        stats
    );
    assert_eq!(
        stats.hoisted_gen_refs, 1,
        "Expected 1 hoisted gen_ref: {:?}",
        stats
    );
    assert_eq!(
        stats.hoisted_projections, 1,
        "Expected 1 hoisted GenDeref projection: {:?}",
        stats
    );
    assert_eq!(
        stats.hoisted_loads, 1,
        "Expected 1 hoisted load: {:?}",
        stats
    );
    assert_eq!(stats.total_hoisted(), 4);

    // Verify all 4 instructions were placed into the preheader (b_preheader = b1)
    let preheader = func.get_block(b_preheader).unwrap();
    assert_eq!(preheader.instructions.len(), 4);

    // Body should now have 0 hoisted instructions
    let body = func.get_block(b_body).unwrap();
    assert_eq!(body.instructions.len(), 0);
}

#[test]
fn test_licm_preserves_gen_ref_when_loop_frees_memory() {
    use ifa_ast::ParamMode;
    use ifa_fir::ir::*;
    use ifa_fir::types::FirType;
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("free_prevents_hoisting");
    let param = FirParam {
        name: INTERNER.intern("base_ptr"),
        val: ValueId(0),
        ty: FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: false,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![param],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b_entry = BlockId(0);
    let b_preheader = func.alloc_block();
    let b_header = func.alloc_block();
    let b_body = func.alloc_block();
    let b_exit = func.alloc_block();

    func.get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_preheader,
            args: Vec::new(),
        });
    func.get_block_mut(b_preheader)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_header,
            args: Vec::new(),
        });

    let v_cond = func.alloc_value();
    func.get_block_mut(b_header)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let v_alloca = func.alloc_value();
    let v_gen_ref = func.alloc_value();

    let body_bb = func.get_block_mut(b_body).unwrap();
    // Alloca is invariant and unaffected by frees
    body_bb.push_instruction(Instruction::new(
        Some(v_alloca),
        ValueExpr::Alloca {
            ty: FirType::Int(IntType::I64),
            name: None,
        },
        Span::DUMMY,
    ));
    // GenFree occurs in loop body!
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenFree { ptr: ValueId(0) },
        Span::DUMMY,
    ));
    // GenRef should NOT be hoisted because memory is freed inside the loop
    body_bb.push_instruction(Instruction::new(
        Some(v_gen_ref),
        ValueExpr::GenRef { ptr: ValueId(0) },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    func.get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));

    let mut licm = LicmPass::new();
    licm.run_on_function(&mut func);

    let stats = licm.stats();
    // Alloca is safely hoisted
    assert_eq!(stats.hoisted_allocs, 1);
    // GenRef MUST NOT be hoisted due to GenFree in loop
    assert_eq!(stats.hoisted_gen_refs, 0);
}

#[test]
fn test_streaming_pipeline_disjoint_arena_load_hoisting() {
    use ifa_ast::ParamMode;
    use ifa_fir::{
        ConstantValue, FirFunction, FirParam, FirType, Instruction, Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let mut func = FirFunction::new(
        INTERNER.intern("stream_filter_loop"),
        vec![FirParam {
            name: INTERNER.intern("len"),
            ty: FirType::Int(IntType::I64),
            val: ValueId(0),
            mode: ParamMode::In,
            noalias: false,
        }],
        FirType::Unit,
        true,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b_entry = func.entry_block;
    let b_header = func.alloc_block();
    let b_body = func.alloc_block();
    let b_exit = func.alloc_block();

    let v_zero = func.alloc_value();
    let v_one = func.alloc_value();
    let v_in_alloc = func.alloc_value();
    let v_out_alloc = func.alloc_value();

    let entry_bb = func.get_block_mut(b_entry).unwrap();
    entry_bb.push_instruction(Instruction::new(
        Some(v_zero),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    entry_bb.push_instruction(Instruction::new(
        Some(v_one),
        ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
        Span::DUMMY,
    ));
    // Allocate input chunk in streaming Arena 101
    entry_bb.push_instruction(Instruction::new(
        Some(v_in_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(101),
        },
        Span::DUMMY,
    ));
    // Allocate output chunk in streaming Arena 102
    entry_bb.push_instruction(Instruction::new(
        Some(v_out_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(102),
        },
        Span::DUMMY,
    ));
    entry_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: vec![v_zero],
    });

    let v_idx = func.alloc_value();
    func.get_block_mut(b_header)
        .unwrap()
        .params
        .push((v_idx, FirType::Int(IntType::I64)));

    let v_cond = func.alloc_value();
    func.get_block_mut(b_header)
        .unwrap()
        .push_instruction(Instruction::new(
            Some(v_cond),
            ValueExpr::Binary {
                op: ifa_fir::BinaryOp::Lt,
                lhs: v_idx,
                rhs: ValueId(0),
            },
            Span::DUMMY,
        ));
    func.get_block_mut(b_header)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let v_load_in = func.alloc_value();
    let v_next_idx = func.alloc_value();
    let body_bb = func.get_block_mut(b_body).unwrap();
    // Load from input chunk in Arena 101 (invariant across loop iterations)
    body_bb.push_instruction(Instruction::new(
        Some(v_load_in),
        ValueExpr::Load { ptr: v_in_alloc },
        Span::DUMMY,
    ));
    // Store into output chunk in Arena 102 (different arena, provably disjoint!)
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::Store {
            ptr: v_out_alloc,
            val: v_load_in,
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(v_next_idx),
        ValueExpr::Binary {
            op: ifa_fir::BinaryOp::Add,
            lhs: v_idx,
            rhs: v_one,
        },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: vec![v_next_idx],
    });

    func.get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));

    let mut licm = LicmPass::new();
    licm.run_on_function(&mut func);

    let stats = licm.stats();
    // The load from Arena 101 must be successfully hoisted out of the loop into the preheader
    assert_eq!(
        stats.hoisted_loads, 1,
        "Load from disjoint arena must be hoisted by LICM"
    );
}

#[test]
fn test_partial_alias_elimination_on_disjoint_composite_paths_under_loop() {
    let src = r#"
        struct State {
            data: i64,
            counter: i64,
        }

        pub fn process_disjoint_loop(mut s: State, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + s.data;
                s.counter = s.counter + 1;
                i = i + 1;
            }
            return acc + s.counter;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("partial_alias.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.eliminated_partial_aliases >= 1 || stats.hoisted_projections >= 1,
        "Disjoint composite field read s.data must have partial alias eliminated or hoisted: {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let state_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("State"),
        fields: vec![FirValue::Int(10), FirValue::Int(0)],
    };

    // 10 * 5 + 5 = 55
    let res = interp
        .execute_function("process_disjoint_loop", vec![state_obj, FirValue::Int(5)])
        .unwrap();
    assert_eq!(res, FirValue::Int(55));
}

#[test]
fn test_partial_alias_elimination_nested_composite_fields() {
    let src = r#"
        struct Metadata {
            tag: i64,
        }

        struct Container {
            meta: Metadata,
            counter: i64,
        }

        pub fn compute_nested(mut c: Container, limit: i64) -> i64 {
            mut sum = 0;
            mut k = 0;
            while k < limit {
                sum = sum + c.meta.tag;
                c.counter = c.counter + 2;
                k = k + 1;
            }
            return sum + c.counter;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("nested_partial_alias.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.loops_optimized >= 1,
        "Loop must be optimized: {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let meta_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Metadata"),
        fields: vec![FirValue::Int(7)],
    };
    let container_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Container"),
        fields: vec![meta_obj, FirValue::Int(0)],
    };

    // 7 * 4 + (2 * 4) = 28 + 8 = 36
    let res = interp
        .execute_function("compute_nested", vec![container_obj, FirValue::Int(4)])
        .unwrap();
    assert_eq!(res, FirValue::Int(36));
}

#[test]
fn test_licm_hoists_invariant_subslice_and_generation_checks_nested_multipass() {
    let src = r#"
        struct BufferRef {
            tag: i64,
        }

        pub fn process_matrix_slices(buf: ref BufferRef, outer_lim: i64, inner_lim: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < outer_lim {
                mut j = 0;
                while j < inner_lim {
                    acc = acc + buf.tag;
                    j = j + 1;
                }
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_nested_slice_gen.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.loops_optimized >= 1,
        "Loops must be optimized: {:?}",
        stats
    );
    assert!(
        stats.total_hoisted() >= 1,
        "Invariant operations must be hoisted: {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let buf_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("BufferRef"),
        fields: vec![FirValue::Int(10)],
    };

    // 10 * 3 * 4 = 120
    let res = interp
        .execute_function(
            "process_matrix_slices",
            vec![buf_obj, FirValue::Int(3), FirValue::Int(4)],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(120));
}

#[test]
fn test_licm_disjoint_symbolic_subslice_hoisting() {
    let src = r#"
        struct PartitionContext {
            pivot_val: i64,
        }

        pub fn process_partitions(ctx: PartitionContext, n: i64) -> i64 {
            mut total = 0;
            mut i = 0;
            while i < n {
                total = total + ctx.pivot_val;
                i = i + 1;
            }
            return total;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_partition.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.hoisted_projections >= 1,
        "Pivot projection must be hoisted: {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let ctx_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("PartitionContext"),
        fields: vec![FirValue::Int(42)],
    };

    let res = interp
        .execute_function("process_partitions", vec![ctx_obj, FirValue::Int(5)])
        .unwrap();
    assert_eq!(res, FirValue::Int(210));
}

#[test]
fn test_licm_coroutine_loop_hoists_gen_ref_and_gen_check() {
    use ifa_ast::ParamMode;
    use ifa_fir::ir::*;
    use ifa_fir::types::FirType;
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("coro_stream_generator");
    let param = FirParam {
        name: INTERNER.intern("base_ptr"),
        val: ValueId(0),
        ty: FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: true,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![param],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let b_entry = BlockId(0);
    let b_preheader = func.alloc_block();
    let b_header = func.alloc_block();
    let b_body = func.alloc_block();
    let b_exit = func.alloc_block();

    func.get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_preheader,
            args: Vec::new(),
        });
    func.get_block_mut(b_preheader)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_header,
            args: Vec::new(),
        });

    let v_cond = func.alloc_value();
    func.get_block_mut(b_header)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let v_gen_ref = func.alloc_value();
    let v_deref = func.alloc_value();
    let v_load = func.alloc_value();

    let body_bb = func.get_block_mut(b_body).unwrap();
    // 1. Invariant GenRef on base_ptr
    body_bb.push_instruction(Instruction::new(
        Some(v_gen_ref),
        ValueExpr::GenRef { ptr: ValueId(0) },
        Span::DUMMY,
    ));
    // 2. Invariant GenCheck on v_gen_ref
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_gen_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));
    // 3. Dereference and load
    body_bb.push_instruction(Instruction::new(
        Some(v_deref),
        ValueExpr::GenDeref { ref_val: v_gen_ref },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(v_load),
        ValueExpr::Load { ptr: v_deref },
        Span::DUMMY,
    ));
    // 4. Yield value (coroutine suspension)
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v_load },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    func.get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));

    let mut licm = LicmPass::new();
    licm.run_on_function(&mut func);

    let stats = licm.stats();
    assert_eq!(
        stats.hoisted_gen_refs, 1,
        "GenRef must be hoisted out of coroutine loop: {:?}",
        stats
    );
    assert_eq!(
        stats.hoisted_gen_checks, 1,
        "GenCheck must be hoisted out of coroutine loop into preheader: {:?}",
        stats
    );
    assert_eq!(
        stats.hoisted_loads, 1,
        "Load must be hoisted out of coroutine loop across yields: {:?}",
        stats
    );
    assert!(
        stats.loops_optimized >= 1,
        "Coroutine loop must be marked as optimized: {:?}",
        stats
    );

    // Verify preheader contains hoisted GenRef and GenCheck
    let preheader = func.get_block(b_preheader).unwrap();
    let has_hoisted_ref = preheader
        .instructions
        .iter()
        .any(|i| matches!(i.expr, ValueExpr::GenRef { .. }));
    let has_hoisted_chk = preheader.instructions.iter().any(|i| {
        matches!(
            i.expr,
            ValueExpr::GenCheck {
                redundant: false,
                ..
            }
        )
    });
    assert!(
        has_hoisted_ref,
        "Preheader must contain hoisted GenRef: {:?}",
        preheader.instructions
    );
    assert!(
        has_hoisted_chk,
        "Preheader must contain hoisted GenCheck: {:?}",
        preheader.instructions
    );

    // Verify loop body contains NO active GenCheck
    let body = func.get_block(b_body).unwrap();
    let active_check_in_body = body.instructions.iter().any(|i| {
        matches!(
            i.expr,
            ValueExpr::GenCheck {
                redundant: false,
                ..
            }
        )
    });
    assert!(
        !active_check_in_body,
        "Coroutine loop body must contain zero active GenCheck instructions: {:?}",
        body.instructions
    );
}

#[test]
fn test_licm_coroutine_generator_stream_multiple_checks_deduplication() {
    use ifa_ast::ParamMode;
    use ifa_fir::ir::*;
    use ifa_fir::types::FirType;
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("coro_multi_chk_stream");
    let param = FirParam {
        name: INTERNER.intern("stream_ref"),
        val: ValueId(0),
        ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: true,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![param],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let b_entry = BlockId(0);
    let b_preheader = func.alloc_block();
    let b_header = func.alloc_block();
    let b_body = func.alloc_block();
    let b_exit = func.alloc_block();

    func.get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_preheader,
            args: Vec::new(),
        });
    func.get_block_mut(b_preheader)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_header,
            args: Vec::new(),
        });

    let v_cond = func.alloc_value();
    func.get_block_mut(b_header)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let body_bb = func.get_block_mut(b_body).unwrap();
    // Two redundant checks on invariant parameter stream_ref in generator loop
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(0),
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(0),
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    func.get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));

    let mut licm = LicmPass::new();
    licm.run_on_function(&mut func);

    let stats = licm.stats();
    assert!(
        stats.hoisted_gen_checks >= 1,
        "At least one GenCheck must be hoisted: {:?}",
        stats
    );

    // Preheader must have exactly 1 hoisted GenCheck
    let preheader = func.get_block(b_preheader).unwrap();
    let chk_count = preheader
        .instructions
        .iter()
        .filter(|i| {
            matches!(
                i.expr,
                ValueExpr::GenCheck {
                    redundant: false,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        chk_count, 1,
        "Preheader must contain exactly 1 hoisted GenCheck: {:?}",
        preheader.instructions
    );

    // Loop body must have 0 active GenChecks
    let body = func.get_block(b_body).unwrap();
    let active_checks = body
        .instructions
        .iter()
        .filter(|i| {
            matches!(
                i.expr,
                ValueExpr::GenCheck {
                    redundant: false,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        active_checks, 0,
        "Loop body must have 0 active checks: {:?}",
        body.instructions
    );
}

#[test]
fn test_licm_async_channel_stream_barrier_elimination_with_interprocedural_pure_helper() {
    use ifa_ast::ParamMode;
    use ifa_fir::ir::*;
    use ifa_fir::types::FirType;
    use ifa_fir::{FirModule, LicmPass};
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let mut module = FirModule::new(INTERNER.intern("async_stream_mod"));

    // 1. Pure helper function: `compute_hash(v: i64) -> i64`
    let helper_name = INTERNER.intern("compute_hash");
    let p_val = FirParam {
        name: INTERNER.intern("v"),
        val: ValueId(0),
        ty: FirType::Int(IntType::I64),
        mode: ParamMode::In,
        noalias: true,
    };
    let mut helper_fn = FirFunction::new(
        helper_name,
        vec![p_val],
        FirType::Int(IntType::I64),
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    let h_entry = BlockId(0);
    let v_one = helper_fn.alloc_value();
    let v_res = helper_fn.alloc_value();
    let h_bb = helper_fn.get_block_mut(h_entry).unwrap();
    h_bb.push_instruction(Instruction::new(
        Some(v_one),
        ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
        Span::DUMMY,
    ));
    h_bb.push_instruction(Instruction::new(
        Some(v_res),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: ValueId(0),
            rhs: v_one,
        },
        Span::DUMMY,
    ));
    h_bb.set_terminator(Terminator::Return(Some(v_res)));
    module.functions.push(helper_fn);

    // 2. Colorless asynchronous stream loop function: `stream_worker(rx: chan, cfg_ref: ref i64)`
    let worker_name = INTERNER.intern("stream_worker");
    let p_chan = FirParam {
        name: INTERNER.intern("rx"),
        val: ValueId(0),
        ty: FirType::Channel(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: true,
    };
    let p_cfg = FirParam {
        name: INTERNER.intern("cfg_ref"),
        val: ValueId(1),
        ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: true,
    };
    let mut worker_fn = FirFunction::new(
        worker_name,
        vec![p_chan, p_cfg],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    worker_fn.next_value_id = 2;

    let b_entry = BlockId(0);
    let b_pre = worker_fn.alloc_block();
    let b_hdr = worker_fn.alloc_block();
    let b_body = worker_fn.alloc_block();
    let b_exit = worker_fn.alloc_block();

    worker_fn
        .get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_pre,
            args: Vec::new(),
        });
    worker_fn
        .get_block_mut(b_pre)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_hdr,
            args: Vec::new(),
        });

    let v_cond = worker_fn.alloc_value();
    let recv_val = worker_fn.alloc_value();
    let hash_val = worker_fn.alloc_value();
    let load_val = worker_fn.alloc_value();

    worker_fn
        .get_block_mut(b_hdr)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let body_bb = worker_fn.get_block_mut(b_body).unwrap();
    // A: Invariant GenCheck on cfg_ref before channel receive
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(1),
            redundant: false,
        },
        Span::DUMMY,
    ));
    // B: Channel receive suspension point
    body_bb.push_instruction(Instruction::new(
        Some(recv_val),
        ValueExpr::ChanRecv { chan: ValueId(0) },
        Span::DUMMY,
    ));
    // C: Second GenCheck following channel receive
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(1),
            redundant: false,
        },
        Span::DUMMY,
    ));
    // D: Interprocedural direct call to pure helper
    body_bb.push_instruction(Instruction::new(
        Some(hash_val),
        ValueExpr::CallDirect {
            name: helper_name,
            args: vec![recv_val],
        },
        Span::DUMMY,
    ));
    // E: Invariant Load on cfg_ref
    body_bb.push_instruction(Instruction::new(
        Some(load_val),
        ValueExpr::Load { ptr: ValueId(1) },
        Span::DUMMY,
    ));
    // F: Coroutine yield suspension point
    body_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    body_bb.set_terminator(Terminator::Branch {
        target: b_hdr,
        args: Vec::new(),
    });

    worker_fn
        .get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));
    module.functions.push(worker_fn);

    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);
    let stats = licm.stats();

    assert!(
        stats.hoisted_gen_checks >= 1,
        "Invariant GenCheck must be hoisted out of channel stream loop: {:?}",
        stats
    );
    assert!(
        stats.coroutine_sync_barriers_eliminated >= 1,
        "Superfluous sync barriers across ChanRecv must be eliminated: {:?}",
        stats
    );
    assert!(
        stats.interprocedural_calls_analyzed >= 1,
        "Pure helper call must be analyzed inter-procedurally: {:?}",
        stats
    );
    assert!(
        stats.hoisted_loads >= 1,
        "Invariant Load across pure helper and channel recv must be hoisted: {:?}",
        stats
    );

    // Verify optimized worker function
    let opt_worker = module
        .functions
        .iter()
        .find(|f| f.name == worker_name)
        .unwrap();
    let pre_b = opt_worker.get_block(b_pre).unwrap();
    let pre_has_gen_chk = pre_b.instructions.iter().any(|i| {
        matches!(
            i.expr,
            ValueExpr::GenCheck {
                redundant: false,
                ref_val,
            } if ref_val == ValueId(1)
        )
    });
    let pre_has_load = pre_b
        .instructions
        .iter()
        .any(|i| matches!(i.expr, ValueExpr::Load { .. }));
    assert!(
        pre_has_gen_chk,
        "Preheader must contain hoisted GenCheck: {:?}",
        pre_b.instructions
    );
    assert!(
        pre_has_load,
        "Preheader must contain hoisted Load: {:?}",
        pre_b.instructions
    );

    // Loop body must have ZERO active GenCheck instructions
    let opt_body = opt_worker.get_block(b_body).unwrap();
    let active_chks = opt_body
        .instructions
        .iter()
        .filter(|i| {
            matches!(
                i.expr,
                ValueExpr::GenCheck {
                    redundant: false,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        active_chks, 0,
        "Stream loop body must contain 0 active GenChecks: {:?}",
        opt_body.instructions
    );
}

#[test]
fn test_licm_intra_loop_dominance_barrier_elimination_across_yield_and_recv() {
    use ifa_fir::ir::*;
    use ifa_fir::types::FirType;
    use ifa_fir::LicmPass;
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("local_barrier_coro");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let b_entry = BlockId(0);
    let b_hdr = func.alloc_block();
    let b_body = func.alloc_block();
    let b_exit = func.alloc_block();

    func.get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_hdr,
            args: Vec::new(),
        });

    let v_cond = func.alloc_value();
    let local_alloc = func.alloc_value();
    let local_ref = func.alloc_value();

    func.get_block_mut(b_hdr)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let body_bb = func.get_block_mut(b_body).unwrap();
    body_bb.push_instruction(Instruction::new(
        Some(local_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(3),
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(local_ref),
        ValueExpr::GenRef { ptr: local_alloc },
        Span::DUMMY,
    ));
    // Initial barrier before suspension
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: local_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));
    // Asynchronous suspension
    body_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    // Superfluous barrier post-suspension
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: local_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_hdr,
        args: Vec::new(),
    });

    func.get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));

    let mut licm = LicmPass::new();
    licm.run_on_function(&mut func);
    let stats = licm.stats();

    assert!(
        stats.coroutine_sync_barriers_eliminated >= 1,
        "Post-yield superfluous check on local ref must be eliminated: {:?}",
        stats
    );

    let opt_body = func.get_block(b_body).unwrap();
    let gen_checks: Vec<bool> = opt_body
        .instructions
        .iter()
        .filter_map(|i| {
            if let ValueExpr::GenCheck { redundant, .. } = i.expr {
                Some(redundant)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        gen_checks.len(),
        2,
        "Expected 2 GenCheck instructions in body"
    );
    // The second GenCheck must be marked redundant!
    assert!(
        gen_checks[1],
        "Second GenCheck after yield must be marked redundant: {:?}",
        gen_checks
    );
}

#[test]
fn test_licm_disjoint_arena_free_callee_does_not_block_gen_check_hoisting() {
    use ifa_ast::ParamMode;
    use ifa_fir::ir::*;
    use ifa_fir::types::FirType;
    use ifa_fir::{FirModule, LicmPass};
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let mut module = FirModule::new(INTERNER.intern("disjoint_free_mod"));

    // 1. Callee freeing memory in disjoint arena 9: `clean_temp_arena()`
    let clean_fn_name = INTERNER.intern("clean_temp_arena");
    let mut clean_fn = FirFunction::new(
        clean_fn_name,
        vec![],
        FirType::Unit,
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    let c_entry = BlockId(0);
    let temp_ptr = clean_fn.alloc_value();
    let c_bb = clean_fn.get_block_mut(c_entry).unwrap();
    c_bb.push_instruction(Instruction::new(
        Some(temp_ptr),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(9),
        },
        Span::DUMMY,
    ));
    c_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenFree { ptr: temp_ptr },
        Span::DUMMY,
    ));
    c_bb.set_terminator(Terminator::Return(None));
    module.functions.push(clean_fn);

    // 2. Caller with loop operating on arena 1 reference
    let caller_name = INTERNER.intern("arena1_stream_worker");
    let p_ref = FirParam {
        name: INTERNER.intern("persistent_ref"),
        val: ValueId(0),
        ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: true,
    };
    let mut caller_fn = FirFunction::new(
        caller_name,
        vec![p_ref],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    caller_fn.is_coroutine = true;

    let b_entry = BlockId(0);
    let b_pre = caller_fn.alloc_block();
    let b_hdr = caller_fn.alloc_block();
    let b_body = caller_fn.alloc_block();
    let b_exit = caller_fn.alloc_block();

    caller_fn
        .get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_pre,
            args: Vec::new(),
        });
    caller_fn
        .get_block_mut(b_pre)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_hdr,
            args: Vec::new(),
        });

    let v_cond = caller_fn.alloc_value();
    caller_fn
        .get_block_mut(b_hdr)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let body_bb = caller_fn.get_block_mut(b_body).unwrap();
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(0),
            redundant: false,
        },
        Span::DUMMY,
    ));
    // Calling clean_temp_arena (which frees in arena 9, distinct from persistent_ref in arena 1)
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::CallDirect {
            name: clean_fn_name,
            args: vec![],
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    // Superfluous barrier post-suspension across disjoint free
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(0),
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_hdr,
        args: Vec::new(),
    });

    caller_fn
        .get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));
    module.functions.push(caller_fn);

    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);
    let stats = licm.stats();

    assert!(
        stats.hoisted_gen_checks >= 1,
        "GenCheck must be hoisted despite disjoint arena free in callee: {:?}",
        stats
    );
    assert!(
        stats.coroutine_sync_barriers_eliminated >= 1,
        "Sync barrier must be eliminated: {:?}",
        stats
    );
}
