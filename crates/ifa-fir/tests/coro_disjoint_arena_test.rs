use ifa_ast::ParamMode;
use ifa_fir::{
    ArenaFusionPass, BinaryOp, FirFunction, FirModule, FirParam, FirType, Instruction, IpoPass,
    Terminator, ValueExpr,
};
use ifa_sema::types::IntType;
use ifa_span::{Span, INTERNER};

#[test]
fn test_coroutine_disjoint_arena_sync_barrier_elimination() {
    let mut module = FirModule::new(INTERNER.intern("test_mod"));

    // Define coroutine function: `coro_stream_worker`
    let coro_name = INTERNER.intern("coro_stream_worker");
    let p0_name = INTERNER.intern("p0");
    let p0_val = ifa_fir::ValueId(0);
    let p0_param = FirParam::new(
        p0_name,
        p0_val,
        FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        ParamMode::In,
    )
    .with_noalias(true);

    let mut func = FirFunction::new(
        coro_name,
        vec![p0_param],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;
    func.next_value_id = 1;

    let b0 = func.entry_block;
    let b1 = func.alloc_block();

    let alloc_a2 = func.alloc_value();
    let gen_ref_a2 = func.alloc_value();
    let chk1_p0 = func.alloc_value();
    let chk1_a2 = func.alloc_value();
    let yield_token = func.alloc_value();
    let chk2_p0 = func.alloc_value();
    let chk2_a2 = func.alloc_value();
    let deref_a2 = func.alloc_value();
    let deref_p0 = func.alloc_value();
    let sum_val = func.alloc_value();

    // Block 0 instructions:
    // 1. GenAlloc in Arena 2 (ID: 2)
    let block0 = func.get_block_mut(b0).unwrap();
    block0.instructions.push(Instruction::new(
        Some(alloc_a2),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(2),
        },
        Span::DUMMY,
    ));

    // 2. GenRef
    block0.instructions.push(Instruction::new(
        Some(gen_ref_a2),
        ValueExpr::GenRef { ptr: alloc_a2 },
        Span::DUMMY,
    ));

    // 3. Initial check on p0
    block0.instructions.push(Instruction::new(
        Some(chk1_p0),
        ValueExpr::GenCheck {
            ref_val: p0_val,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // 4. Initial check on gen_ref_a2
    block0.instructions.push(Instruction::new(
        Some(chk1_a2),
        ValueExpr::GenCheck {
            ref_val: gen_ref_a2,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // 5. Coroutine suspension point: Yield
    block0.instructions.push(Instruction::new(
        Some(yield_token),
        ValueExpr::Yield,
        Span::DUMMY,
    ));

    // 6. Branch to Block 1
    block0.terminator = Some(Terminator::Branch {
        target: b1,
        args: Vec::new(),
    });

    // Block 1 (post-suspension resumption):
    let block1 = func.get_block_mut(b1).unwrap();

    // 7. Check on p0 after suspension
    block1.instructions.push(Instruction::new(
        Some(chk2_p0),
        ValueExpr::GenCheck {
            ref_val: p0_val,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // 8. Check on gen_ref_a2 after suspension
    block1.instructions.push(Instruction::new(
        Some(chk2_a2),
        ValueExpr::GenCheck {
            ref_val: gen_ref_a2,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // 9. GenDeref and computations
    block1.instructions.push(Instruction::new(
        Some(deref_a2),
        ValueExpr::GenDeref {
            ref_val: gen_ref_a2,
        },
        Span::DUMMY,
    ));

    block1.instructions.push(Instruction::new(
        Some(deref_p0),
        ValueExpr::GenDeref { ref_val: p0_val },
        Span::DUMMY,
    ));

    block1.instructions.push(Instruction::new(
        Some(sum_val),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: deref_a2,
            rhs: deref_p0,
        },
        Span::DUMMY,
    ));

    block1.terminator = Some(Terminator::Return(Some(sum_val)));

    module.functions.push(func);

    // Caller function: allocates in Arena 1 and calls coroutine
    let caller_name = INTERNER.intern("main_pipeline");
    let mut caller = FirFunction::new(
        caller_name,
        Vec::new(),
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let cb0 = caller.entry_block;

    let a1_alloc = caller.alloc_value();
    let a1_ref = caller.alloc_value();
    let call_res = caller.alloc_value();

    let cblock = caller.get_block_mut(cb0).unwrap();
    cblock.instructions.push(Instruction::new(
        Some(a1_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(1),
        },
        Span::DUMMY,
    ));

    cblock.instructions.push(Instruction::new(
        Some(a1_ref),
        ValueExpr::GenRef { ptr: a1_alloc },
        Span::DUMMY,
    ));

    cblock.instructions.push(Instruction::new(
        Some(call_res),
        ValueExpr::CallDirect {
            name: coro_name,
            args: vec![a1_ref],
        },
        Span::DUMMY,
    ));

    cblock.terminator = Some(Terminator::Return(Some(call_res)));
    module.functions.push(caller);

    // Run Inter-procedural optimization pass
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);
    let ipo_stats = ipo_pass.stats();

    // Verify IPO tracked coroutine disjoint arenas and eliminated superfluous barriers
    assert!(
        ipo_stats.coroutine_disjoint_arenas_analyzed >= 1,
        "Expected at least 1 coroutine analyzed for disjoint arena references, got {}",
        ipo_stats.coroutine_disjoint_arenas_analyzed
    );

    assert!(
        ipo_stats.coroutine_sync_barriers_eliminated >= 1,
        "Expected superfluous coroutine synchronization barriers to be eliminated, got {}",
        ipo_stats.coroutine_sync_barriers_eliminated
    );

    // Verify the instructions inside coro_stream_worker
    let optimized_coro = module
        .functions
        .iter()
        .find(|f| f.name == coro_name)
        .expect("coro_stream_worker must exist");

    let b1_checks: Vec<bool> = optimized_coro
        .blocks
        .iter()
        .find(|b| b.id == b1)
        .unwrap()
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

    assert!(
        !b1_checks.is_empty(),
        "Block 1 must contain checked instructions"
    );
    assert!(
        b1_checks.iter().all(|&r| r),
        "All GenCheck barriers following coroutine yield must be marked redundant: {:?}",
        b1_checks
    );
}

#[test]
fn test_arena_fusion_pass_preserves_disjoint_coroutine_arenas() {
    let mut module = FirModule::new(INTERNER.intern("arena_test_mod"));

    let coro_name = INTERNER.intern("coro_pipeline_stage");
    let mut func = FirFunction::new(
        coro_name,
        Vec::new(),
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let b0 = func.entry_block;
    let val_alloc = func.alloc_value();
    let val_ref = func.alloc_value();
    let yield_v = func.alloc_value();
    let post_chk = func.alloc_value();

    let bb = func.get_block_mut(b0).unwrap();
    bb.instructions.push(Instruction::new(
        Some(val_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(42),
        },
        Span::DUMMY,
    ));

    bb.instructions.push(Instruction::new(
        Some(val_ref),
        ValueExpr::GenRef { ptr: val_alloc },
        Span::DUMMY,
    ));

    bb.instructions.push(Instruction::new(
        Some(yield_v),
        ValueExpr::YieldValue { val: val_ref },
        Span::DUMMY,
    ));

    bb.instructions.push(Instruction::new(
        Some(post_chk),
        ValueExpr::GenCheck {
            ref_val: val_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));

    bb.terminator = Some(Terminator::Return(Some(yield_v)));
    module.functions.push(func);

    let mut arena_pass = ArenaFusionPass::new();
    let stats = arena_pass.run_on_module(&mut module);

    assert!(
        stats.coroutine_sync_barriers_eliminated >= 1,
        "ArenaFusionPass must eliminate redundant coroutine sync barrier: {:?}",
        stats
    );
    assert!(
        stats.disjoint_arena_references_preserved >= 1,
        "ArenaFusionPass must preserve disjoint arena references across yield: {:?}",
        stats
    );

    let coro = module
        .functions
        .iter()
        .find(|f| f.name == coro_name)
        .unwrap();
    let chk = coro.blocks[0]
        .instructions
        .iter()
        .find(|i| matches!(i.expr, ValueExpr::GenCheck { .. }))
        .unwrap();

    if let ValueExpr::GenCheck { redundant, .. } = chk.expr {
        assert!(redundant, "Post-yield GenCheck must be marked redundant");
    }
}

#[test]
fn test_channel_suspension_disjoint_arena_barriers_elimination() {
    let mut module = FirModule::new(INTERNER.intern("chan_test_mod"));

    let coro_name = INTERNER.intern("coro_channel_consumer");
    let mut func = FirFunction::new(
        coro_name,
        Vec::new(),
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let b0 = func.entry_block;
    let b1 = func.alloc_block();

    let chan_val = func.alloc_value();
    let local_arena_alloc = func.alloc_value();
    let local_ref = func.alloc_value();
    let recv_val = func.alloc_value();
    let post_recv_chk = func.alloc_value();
    let final_res = func.alloc_value();

    let bb0 = func.get_block_mut(b0).unwrap();
    // 1. Create channel
    bb0.instructions.push(Instruction::new(
        Some(chan_val),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    // 2. Allocate in disjoint arena (ID: 10)
    bb0.instructions.push(Instruction::new(
        Some(local_arena_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(10),
        },
        Span::DUMMY,
    ));

    // 3. GenRef
    bb0.instructions.push(Instruction::new(
        Some(local_ref),
        ValueExpr::GenRef {
            ptr: local_arena_alloc,
        },
        Span::DUMMY,
    ));

    // 4. Branch to b1
    bb0.terminator = Some(Terminator::Branch {
        target: b1,
        args: Vec::new(),
    });

    let bb1 = func.get_block_mut(b1).unwrap();
    // 5. Channel receive (suspension point)
    bb1.instructions.push(Instruction::new(
        Some(recv_val),
        ValueExpr::ChanRecv { chan: chan_val },
        Span::DUMMY,
    ));

    // 6. GenCheck on local_ref after suspension
    bb1.instructions.push(Instruction::new(
        Some(post_recv_chk),
        ValueExpr::GenCheck {
            ref_val: local_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // 7. GenDeref
    bb1.instructions.push(Instruction::new(
        Some(final_res),
        ValueExpr::GenDeref { ref_val: local_ref },
        Span::DUMMY,
    ));

    bb1.terminator = Some(Terminator::Return(Some(final_res)));
    module.functions.push(func);

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);
    let ipo_stats = ipo_pass.stats();

    assert!(
        ipo_stats.coroutine_sync_barriers_eliminated >= 1,
        "Barrier following channel receive suspension must be eliminated: {:?}",
        ipo_stats
    );

    let opt_coro = module
        .functions
        .iter()
        .find(|f| f.name == coro_name)
        .unwrap();
    let chk = opt_coro.blocks[1]
        .instructions
        .iter()
        .find(|i| matches!(i.expr, ValueExpr::GenCheck { .. }))
        .unwrap();

    if let ValueExpr::GenCheck { redundant, .. } = chk.expr {
        assert!(
            redundant,
            "GenCheck following ChanRecv must be statically redundant"
        );
    }
}

#[test]
fn test_interpreter_coroutine_disjoint_arena_determinism() {
    let mut module = FirModule::new(INTERNER.intern("interp_mod"));

    let coro_name = INTERNER.intern("coro_calc");
    let mut func = FirFunction::new(
        coro_name,
        Vec::new(),
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b0 = func.entry_block;
    let b1 = func.alloc_block();

    let a_alloc = func.alloc_value();
    let a_ref = func.alloc_value();
    let c99 = func.alloc_value();
    let y_tok = func.alloc_value();
    let chk_val = func.alloc_value();
    let deref_val = func.alloc_value();

    let bb0 = func.get_block_mut(b0).unwrap();
    bb0.instructions.push(Instruction::new(
        Some(a_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(7),
        },
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(a_ref),
        ValueExpr::GenRef { ptr: a_alloc },
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(c99),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(99, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::Store {
            ptr: a_alloc,
            val: c99,
        },
        Span::DUMMY,
    ));
    bb0.instructions
        .push(Instruction::new(Some(y_tok), ValueExpr::Yield, Span::DUMMY));
    bb0.terminator = Some(Terminator::Branch {
        target: b1,
        args: Vec::new(),
    });

    let bb1 = func.get_block_mut(b1).unwrap();
    bb1.instructions.push(Instruction::new(
        Some(chk_val),
        ValueExpr::GenCheck {
            ref_val: a_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb1.instructions.push(Instruction::new(
        Some(deref_val),
        ValueExpr::GenDeref { ref_val: a_ref },
        Span::DUMMY,
    ));
    bb1.terminator = Some(Terminator::Return(Some(deref_val)));

    module.functions.push(func);

    // Optimize with ArenaFusionPass and IpoPass
    let mut arena_pass = ArenaFusionPass::new();
    arena_pass.run_on_module(&mut module);

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    // Run in interpreter to assert exact semantic correctness
    let mut interp = ifa_fir::FirInterpreter::new(&module);
    let res = interp
        .execute_function("coro_calc", Vec::new())
        .expect("Interpreter execution must succeed");

    assert_eq!(
        res,
        ifa_fir::FirValue::Int(99),
        "Interpreter must evaluate to exactly 99"
    );
}

#[test]
fn test_coroutine_loop_inout_composite_and_slice_gen_check_elision() {
    let mut module = FirModule::new(INTERNER.intern("coro_composite_mod"));

    // Coroutine stream processor mutating an inout composite struct and slice in a loop
    let coro_name = INTERNER.intern("coro_composite_stream_worker");
    let pt_sym = INTERNER.intern("pt");
    let buf_sym = INTERNER.intern("buf");

    let pt_val = ifa_fir::ValueId(0);
    let buf_val = ifa_fir::ValueId(1);

    let pt_param = FirParam::new(
        pt_sym,
        pt_val,
        FirType::GenerationalRef(Box::new(FirType::Struct(
            INTERNER.intern("Point"),
            vec![
                (INTERNER.intern("x"), FirType::Int(IntType::I64)),
                (INTERNER.intern("y"), FirType::Int(IntType::I64)),
            ],
        ))),
        ParamMode::InOut,
    );
    let buf_param = FirParam::new(
        buf_sym,
        buf_val,
        FirType::GenerationalRef(Box::new(FirType::Slice(Box::new(FirType::Int(
            IntType::I64,
        ))))),
        ParamMode::InOut,
    );

    let mut func = FirFunction::new(
        coro_name,
        vec![pt_param, buf_param],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;
    func.next_value_id = 2;

    // CFG: entry -> preheader -> header -> body -> latch -> header
    //                                  \-> exit
    let b_entry = func.entry_block;
    let b_pre = func.alloc_block();
    let b_head = func.alloc_block();
    let b_body = func.alloc_block();
    let b_latch = func.alloc_block();
    let b_exit = func.alloc_block();

    // Entry block jumps to preheader
    func.get_block_mut(b_entry).unwrap().terminator = Some(Terminator::Branch {
        target: b_pre,
        args: Vec::new(),
    });

    // Preheader initializes iteration counter and jumps to loop header
    let zero_const = func.alloc_value();
    let limit_const = func.alloc_value();
    let one_const = func.alloc_value();

    let pre_b = func.get_block_mut(b_pre).unwrap();
    pre_b.instructions.push(Instruction::new(
        Some(zero_const),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    pre_b.instructions.push(Instruction::new(
        Some(limit_const),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(10, IntType::I64)),
        Span::DUMMY,
    ));
    pre_b.instructions.push(Instruction::new(
        Some(one_const),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(1, IntType::I64)),
        Span::DUMMY,
    ));
    pre_b.terminator = Some(Terminator::Branch {
        target: b_head,
        args: vec![zero_const],
    });

    // Header has loop counter param (phi node)
    let iter_var = func.alloc_value();
    let cmp_res = func.alloc_value();
    let head_b = func.get_block_mut(b_head).unwrap();
    head_b.params.push((iter_var, FirType::Int(IntType::I64)));

    head_b.instructions.push(Instruction::new(
        Some(cmp_res),
        ValueExpr::Binary {
            op: BinaryOp::Lt,
            lhs: iter_var,
            rhs: limit_const,
        },
        Span::DUMMY,
    ));
    head_b.terminator = Some(Terminator::BranchCond {
        cond: cmp_res,
        then_block: b_body,
        then_args: Vec::new(),
        else_block: b_exit,
        else_args: Vec::new(),
    });

    // Body block:
    // 1. Projections on struct pt
    let f0_val = func.alloc_value();
    let f1_ptr = func.alloc_value();
    let chk_pt_1 = func.alloc_value();
    let chk_f0 = func.alloc_value();
    let chk_f1 = func.alloc_value();
    let new_f0 = func.alloc_value();

    // 2. Projections and mutation on slice buf
    let elem_ptr = func.alloc_value();
    let chk_buf_1 = func.alloc_value();
    let chk_elem = func.alloc_value();
    let elem_val = func.alloc_value();

    // 3. Coroutine suspension and post-suspension checks
    let yield_res = func.alloc_value();
    let chk_pt_post = func.alloc_value();
    let chk_buf_post = func.alloc_value();

    let body_b = func.get_block_mut(b_body).unwrap();

    // GenCheck on struct pt
    body_b.instructions.push(Instruction::new(
        Some(chk_pt_1),
        ValueExpr::GenCheck {
            ref_val: pt_val,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // GetField on field 0
    body_b.instructions.push(Instruction::new(
        Some(f0_val),
        ValueExpr::GetField {
            base: pt_val,
            field_idx: 0,
            field_name: INTERNER.intern("x"),
        },
        Span::DUMMY,
    ));

    // GenCheck on field 0
    body_b.instructions.push(Instruction::new(
        Some(chk_f0),
        ValueExpr::GenCheck {
            ref_val: f0_val,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // Inout mutation on field 0: SetField
    body_b.instructions.push(Instruction::new(
        Some(new_f0),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: f0_val,
            rhs: one_const,
        },
        Span::DUMMY,
    ));
    body_b.instructions.push(Instruction::new(
        None,
        ValueExpr::SetField {
            base: pt_val,
            field_idx: 0,
            val: new_f0,
        },
        Span::DUMMY,
    ));

    // GetFieldPtr on field 1
    body_b.instructions.push(Instruction::new(
        Some(f1_ptr),
        ValueExpr::GetFieldPtr {
            base: pt_val,
            field_idx: 1,
            field_name: INTERNER.intern("y"),
        },
        Span::DUMMY,
    ));

    // GenCheck on field 1 pointer
    body_b.instructions.push(Instruction::new(
        Some(chk_f1),
        ValueExpr::GenCheck {
            ref_val: f1_ptr,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // Inout mutation on field 1: Store through field pointer
    body_b.instructions.push(Instruction::new(
        None,
        ValueExpr::Store {
            ptr: f1_ptr,
            val: new_f0,
        },
        Span::DUMMY,
    ));

    // Slice operations: GenCheck, GetElementPtr, and Store
    body_b.instructions.push(Instruction::new(
        Some(chk_buf_1),
        ValueExpr::GenCheck {
            ref_val: buf_val,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_b.instructions.push(Instruction::new(
        Some(elem_ptr),
        ValueExpr::GetElementPtr {
            base: buf_val,
            index: iter_var,
        },
        Span::DUMMY,
    ));
    body_b.instructions.push(Instruction::new(
        Some(chk_elem),
        ValueExpr::GenCheck {
            ref_val: elem_ptr,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_b.instructions.push(Instruction::new(
        Some(elem_val),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(42, IntType::I64)),
        Span::DUMMY,
    ));
    body_b.instructions.push(Instruction::new(
        None,
        ValueExpr::SetElement {
            base: buf_val,
            index: iter_var,
            val: elem_val,
        },
        Span::DUMMY,
    ));

    // Coroutine suspension point: YieldValue
    body_b.instructions.push(Instruction::new(
        Some(yield_res),
        ValueExpr::YieldValue { val: new_f0 },
        Span::DUMMY,
    ));

    // Post-suspension generational checks
    body_b.instructions.push(Instruction::new(
        Some(chk_pt_post),
        ValueExpr::GenCheck {
            ref_val: pt_val,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_b.instructions.push(Instruction::new(
        Some(chk_buf_post),
        ValueExpr::GenCheck {
            ref_val: buf_val,
            redundant: false,
        },
        Span::DUMMY,
    ));

    body_b.terminator = Some(Terminator::Branch {
        target: b_latch,
        args: Vec::new(),
    });

    // Latch block increments loop counter and jumps back to header
    let next_iter = func.alloc_value();
    let latch_b = func.get_block_mut(b_latch).unwrap();
    latch_b.instructions.push(Instruction::new(
        Some(next_iter),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: iter_var,
            rhs: one_const,
        },
        Span::DUMMY,
    ));
    latch_b.terminator = Some(Terminator::Branch {
        target: b_head,
        args: vec![next_iter],
    });

    // Exit block returns 0
    let exit_b = func.get_block_mut(b_exit).unwrap();
    exit_b.terminator = Some(Terminator::Return(Some(zero_const)));

    module.functions.push(func);

    // Run GenerationalOptPass, LicmPass, and IpoPass
    let mut gen_pass = ifa_fir::GenerationalOptPass::new();
    gen_pass.run_on_module(&mut module);
    let gen_stats = gen_pass.stats();

    let mut licm_pass = ifa_fir::LicmPass::new();
    licm_pass.run_on_module(&mut module);

    let mut ipo_pass = ifa_fir::IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    // Verify statistics
    assert!(
        gen_stats.hoisted_checks >= 1,
        "Expected invariant generational check to be hoisted to preheader, got {}",
        gen_stats.hoisted_checks
    );
    assert!(
        gen_stats.eliminated_checks >= 5,
        "Expected at least 5 checks eliminated in coroutine loop, got {}",
        gen_stats.eliminated_checks
    );
    assert!(
        gen_stats.coroutine_sync_barriers_eliminated >= 5,
        "Expected at least 5 coroutine sync barriers eliminated, got {}",
        gen_stats.coroutine_sync_barriers_eliminated
    );

    // Verify all GenCheck instructions inside the loop body are marked redundant
    let opt_func = module
        .functions
        .iter()
        .find(|f| f.name == coro_name)
        .expect("coro_composite_stream_worker must exist");

    let body_checks: Vec<bool> = opt_func
        .get_block(b_body)
        .unwrap()
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

    assert!(
        !body_checks.is_empty(),
        "Body block must contain checked instructions"
    );
    assert!(
        body_checks.iter().all(|&r| r),
        "All GenCheck instructions inside coroutine loop mutating inout composites/slices must be marked redundant: {:?}",
        body_checks
    );
}
