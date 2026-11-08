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
