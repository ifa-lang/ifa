//! Tests for stackless coroutine state machine lowering in the Cranelift JIT backend.

use ifa_codegen_cranelift::JitEngine;
use ifa_fir::{
    BlockId, ConstantValue, FirFunction, FirModule, FirParam, FirType, Instruction, Terminator,
    ValueExpr, ValueId,
};
use ifa_runtime::{
    ifa_rt_coro_destroy, ifa_rt_coro_frame, ifa_rt_coro_is_done, ifa_rt_coro_resume, IfaCoroutine,
};
use ifa_sema::types::IntType;
use ifa_span::{Span, INTERNER};

#[test]
fn test_cranelift_jit_stackless_coroutine_state_machine_steps() {
    let mut module = FirModule::new(INTERNER.intern("coro_steps_mod"));
    let gen_name = INTERNER.intern("generator_steps");

    let mut func = FirFunction::new(
        gen_name,
        vec![],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let v100 = func.alloc_value();
    let v200 = func.alloc_value();
    let v300 = func.alloc_value();

    let b_entry = BlockId(0);
    let entry_bb = func.get_block_mut(b_entry).unwrap();

    // Step 1: YieldValue 100
    entry_bb.push_instruction(Instruction::new(
        Some(v100),
        ValueExpr::Constant(ConstantValue::Int(100, IntType::I64)),
        Span::DUMMY,
    ));
    entry_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v100 },
        Span::DUMMY,
    ));

    // Step 2: YieldValue 200
    entry_bb.push_instruction(Instruction::new(
        Some(v200),
        ValueExpr::Constant(ConstantValue::Int(200, IntType::I64)),
        Span::DUMMY,
    ));
    entry_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v200 },
        Span::DUMMY,
    ));

    // Step 3: Return 300
    entry_bb.push_instruction(Instruction::new(
        Some(v300),
        ValueExpr::Constant(ConstantValue::Int(300, IntType::I64)),
        Span::DUMMY,
    ));
    entry_bb.set_terminator(Terminator::Return(Some(v300)));

    assert!(func.is_coroutine());
    module.functions.push(func);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile stackless coroutine to Cranelift machine code");

    // Execute the factory function to instantiate coroutine frame
    let factory_res = jit
        .run_function("generator_steps")
        .expect("Failed to call coroutine factory");
    let coro_ptr = factory_res as *mut IfaCoroutine;
    assert!(!coro_ptr.is_null(), "Coroutine handle must be non-null");

    unsafe {
        assert_eq!(ifa_rt_coro_is_done(coro_ptr), 0);
        let frame = ifa_rt_coro_frame(coro_ptr);
        assert!(!frame.is_null());

        // Step 1
        let step1_status = ifa_rt_coro_resume(coro_ptr);
        assert_eq!(step1_status, 0, "Step 1 must suspend");
        let step1_val = *(frame.add(8) as *const i64);
        assert_eq!(step1_val, 100, "First yield value must be 100");
        assert_eq!(ifa_rt_coro_is_done(coro_ptr), 0);

        // Step 2
        let step2_status = ifa_rt_coro_resume(coro_ptr);
        assert_eq!(step2_status, 0, "Step 2 must suspend");
        let step2_val = *(frame.add(8) as *const i64);
        assert_eq!(step2_val, 200, "Second yield value must be 200");
        assert_eq!(ifa_rt_coro_is_done(coro_ptr), 0);

        // Step 3 (Completion)
        let step3_status = ifa_rt_coro_resume(coro_ptr);
        assert_eq!(step3_status, 1, "Step 3 must complete");
        let step3_val = *(frame.add(8) as *const i64);
        assert_eq!(step3_val, 300, "Return value must be 300");
        assert_eq!(ifa_rt_coro_is_done(coro_ptr), 1);

        ifa_rt_coro_destroy(coro_ptr);
    }
}

#[test]
fn test_cranelift_jit_stackless_coroutine_with_arguments_and_state() {
    let mut module = FirModule::new(INTERNER.intern("coro_args_mod"));
    let gen_name = INTERNER.intern("accumulator_generator");

    let p_val = ValueId(0);
    let mut func = FirFunction::new(
        gen_name,
        vec![FirParam {
            name: INTERNER.intern("initial"),
            ty: FirType::Int(IntType::I64),
            val: p_val,
            mode: ifa_ast::ParamMode::In,
            noalias: false,
        }],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.next_value_id = 1;

    let v50 = func.alloc_value();
    let v_sum1 = func.alloc_value();
    let v25 = func.alloc_value();
    let v_sum2 = func.alloc_value();

    let b_entry = BlockId(0);
    let entry_bb = func.get_block_mut(b_entry).unwrap();

    // Accumulate: v_sum1 = initial + 50
    entry_bb.push_instruction(Instruction::new(
        Some(v50),
        ValueExpr::Constant(ConstantValue::Int(50, IntType::I64)),
        Span::DUMMY,
    ));
    entry_bb.push_instruction(Instruction::new(
        Some(v_sum1),
        ValueExpr::Binary {
            op: ifa_fir::BinaryOp::Add,
            lhs: p_val,
            rhs: v50,
        },
        Span::DUMMY,
    ));
    entry_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v_sum1 },
        Span::DUMMY,
    ));

    // Yield again: v_sum2 = v_sum1 + 25
    entry_bb.push_instruction(Instruction::new(
        Some(v25),
        ValueExpr::Constant(ConstantValue::Int(25, IntType::I64)),
        Span::DUMMY,
    ));
    entry_bb.push_instruction(Instruction::new(
        Some(v_sum2),
        ValueExpr::Binary {
            op: ifa_fir::BinaryOp::Add,
            lhs: v_sum1,
            rhs: v25,
        },
        Span::DUMMY,
    ));
    entry_bb.set_terminator(Terminator::Return(Some(v_sum2)));

    assert!(func.is_coroutine());
    module.functions.push(func);

    // Caller helper that invokes accumulator_generator(1000)
    let caller_name = INTERNER.intern("run_test");
    let mut caller = FirFunction::new(
        caller_name,
        vec![],
        FirType::Pointer(Box::new(FirType::Unit)),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let v_init = caller.alloc_value();
    let coro_inst = caller.alloc_value();
    let caller_bb = caller.get_block_mut(BlockId(0)).unwrap();
    caller_bb.push_instruction(Instruction::new(
        Some(v_init),
        ValueExpr::Constant(ConstantValue::Int(1000, IntType::I64)),
        Span::DUMMY,
    ));
    caller_bb.push_instruction(Instruction::new(
        Some(coro_inst),
        ValueExpr::CallDirect {
            name: gen_name,
            args: vec![v_init],
        },
        Span::DUMMY,
    ));
    caller_bb.set_terminator(Terminator::Return(Some(coro_inst)));
    module.functions.push(caller);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile accumulator coroutine");

    let hdl_res = jit.run_function("run_test").expect("Failed to run caller");
    let coro_ptr = hdl_res as *mut IfaCoroutine;
    assert!(!coro_ptr.is_null());

    unsafe {
        let frame = ifa_rt_coro_frame(coro_ptr);

        // Step 1: 1000 + 50 = 1050
        let s1 = ifa_rt_coro_resume(coro_ptr);
        assert_eq!(s1, 0);
        let val1 = *(frame.add(8) as *const i64);
        assert_eq!(val1, 1050);

        // Step 2: 1050 + 25 = 1075
        let s2 = ifa_rt_coro_resume(coro_ptr);
        assert_eq!(s2, 1);
        let val2 = *(frame.add(8) as *const i64);
        assert_eq!(val2, 1075);
        assert_eq!(ifa_rt_coro_is_done(coro_ptr), 1);

        ifa_rt_coro_destroy(coro_ptr);
    }
}

#[test]
fn test_cranelift_jit_spawn_coroutine_scheduler() {
    let mut module = FirModule::new(INTERNER.intern("coro_spawn_mod"));
    let worker_name = INTERNER.intern("coro_worker");

    let mut func = FirFunction::new(
        worker_name,
        vec![],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let entry_bb = func.get_block_mut(BlockId(0)).unwrap();
    entry_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    entry_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    entry_bb.set_terminator(Terminator::Return(None));
    assert!(func.is_coroutine());
    module.functions.push(func);

    // Main spawns worker coroutine
    let main_name = INTERNER.intern("main");
    let mut main_func = FirFunction::new(
        main_name,
        vec![],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let spawn_res = main_func.alloc_value();
    let m_bb = main_func.get_block_mut(BlockId(0)).unwrap();
    m_bb.push_instruction(Instruction::new(
        Some(spawn_res),
        ValueExpr::Spawn {
            target: worker_name,
            args: vec![],
        },
        Span::DUMMY,
    ));
    m_bb.set_terminator(Terminator::Return(Some(spawn_res)));
    module.functions.push(main_func);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile spawned coroutine");

    let fid = jit
        .run_main()
        .expect("Failed to run main spawning coroutine");
    assert!(fid > 0, "Spawn must return a positive FiberId");
}

#[test]
fn test_cranelift_jit_stackless_coroutine_branching_with_yield() {
    let mut module = FirModule::new(INTERNER.intern("coro_branch_mod"));
    let gen_name = INTERNER.intern("branching_generator");

    let p_flag = ValueId(0);
    let mut func = FirFunction::new(
        gen_name,
        vec![FirParam {
            name: INTERNER.intern("flag"),
            ty: FirType::Bool,
            val: p_flag,
            mode: ifa_ast::ParamMode::In,
            noalias: false,
        }],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.next_value_id = 1;

    let b_entry = BlockId(0);
    let b_then = func.alloc_block();
    let b_else = func.alloc_block();
    let b_merge = func.alloc_block();

    let entry_bb = func.get_block_mut(b_entry).unwrap();
    entry_bb.set_terminator(Terminator::BranchCond {
        cond: p_flag,
        then_block: b_then,
        then_args: Vec::new(),
        else_block: b_else,
        else_args: Vec::new(),
    });

    // Then branch: define v_then = 42, yield 42, jump to merge
    let v_then = func.alloc_value();
    let then_bb = func.get_block_mut(b_then).unwrap();
    then_bb.push_instruction(Instruction::new(
        Some(v_then),
        ValueExpr::Constant(ConstantValue::Int(42, IntType::I64)),
        Span::DUMMY,
    ));
    then_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v_then },
        Span::DUMMY,
    ));
    then_bb.set_terminator(Terminator::Branch {
        target: b_merge,
        args: vec![v_then],
    });

    // Else branch: define v_else = 99, yield 99, jump to merge
    let v_else = func.alloc_value();
    let else_bb = func.get_block_mut(b_else).unwrap();
    else_bb.push_instruction(Instruction::new(
        Some(v_else),
        ValueExpr::Constant(ConstantValue::Int(99, IntType::I64)),
        Span::DUMMY,
    ));
    else_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v_else },
        Span::DUMMY,
    ));
    else_bb.set_terminator(Terminator::Branch {
        target: b_merge,
        args: vec![v_else],
    });

    // Merge block: receives result, returns result + 1
    let v_param = func.alloc_value();
    let v_one = func.alloc_value();
    let v_res = func.alloc_value();
    let merge_bb = func.get_block_mut(b_merge).unwrap();
    merge_bb.params.push((v_param, FirType::Int(IntType::I64)));
    merge_bb.push_instruction(Instruction::new(
        Some(v_one),
        ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
        Span::DUMMY,
    ));
    merge_bb.push_instruction(Instruction::new(
        Some(v_res),
        ValueExpr::Binary {
            op: ifa_fir::BinaryOp::Add,
            lhs: v_param,
            rhs: v_one,
        },
        Span::DUMMY,
    ));
    merge_bb.set_terminator(Terminator::Return(Some(v_res)));

    assert!(func.is_coroutine());
    module.functions.push(func);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile branching coroutine to Cranelift machine code");

    // Test with true branch (flag = true)
    let caller_true = INTERNER.intern("call_true");
    let mut c_true = FirFunction::new(
        caller_true,
        vec![],
        FirType::Pointer(Box::new(FirType::Unit)),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let v_true = c_true.alloc_value();
    let c_true_inst = c_true.alloc_value();
    let c_true_bb = c_true.get_block_mut(BlockId(0)).unwrap();
    c_true_bb.push_instruction(Instruction::new(
        Some(v_true),
        ValueExpr::Constant(ConstantValue::Bool(true)),
        Span::DUMMY,
    ));
    c_true_bb.push_instruction(Instruction::new(
        Some(c_true_inst),
        ValueExpr::CallDirect {
            name: gen_name,
            args: vec![v_true],
        },
        Span::DUMMY,
    ));
    c_true_bb.set_terminator(Terminator::Return(Some(c_true_inst)));

    let mut jit_true = JitEngine::new().expect("Failed to initialize JIT");
    let mut mod_true = module.clone();
    mod_true.functions.push(c_true);
    jit_true
        .compile_module(&mod_true)
        .expect("Failed to compile true module");

    let hdl_res = jit_true
        .run_function("call_true")
        .expect("Failed to call call_true");
    let coro_ptr = hdl_res as *mut IfaCoroutine;
    assert!(!coro_ptr.is_null());

    unsafe {
        let frame = ifa_rt_coro_frame(coro_ptr);
        // Step 1: YieldValue 42
        let s1 = ifa_rt_coro_resume(coro_ptr);
        assert_eq!(s1, 0, "Should suspend at then yield");
        let val1 = *(frame.add(8) as *const i64);
        assert_eq!(val1, 42, "Then yield value must be 42");

        // Step 2: Merge Return 42 + 1 = 43
        let s2 = ifa_rt_coro_resume(coro_ptr);
        assert_eq!(s2, 1, "Should complete at return");
        let val2 = *(frame.add(8) as *const i64);
        assert_eq!(val2, 43, "Merged return value must be 43");
        assert_eq!(ifa_rt_coro_is_done(coro_ptr), 1);

        ifa_rt_coro_destroy(coro_ptr);
    }

    // Test with false branch (flag = false)
    let caller_false = INTERNER.intern("call_false");
    let mut c_false = FirFunction::new(
        caller_false,
        vec![],
        FirType::Pointer(Box::new(FirType::Unit)),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let v_false = c_false.alloc_value();
    let c_false_inst = c_false.alloc_value();
    let c_false_bb = c_false.get_block_mut(BlockId(0)).unwrap();
    c_false_bb.push_instruction(Instruction::new(
        Some(v_false),
        ValueExpr::Constant(ConstantValue::Bool(false)),
        Span::DUMMY,
    ));
    c_false_bb.push_instruction(Instruction::new(
        Some(c_false_inst),
        ValueExpr::CallDirect {
            name: gen_name,
            args: vec![v_false],
        },
        Span::DUMMY,
    ));
    c_false_bb.set_terminator(Terminator::Return(Some(c_false_inst)));

    let mut jit_false = JitEngine::new().expect("Failed to initialize JIT");
    let mut mod_false = module.clone();
    mod_false.functions.push(c_false);
    jit_false
        .compile_module(&mod_false)
        .expect("Failed to compile false module");

    let hdl_res_false = jit_false
        .run_function("call_false")
        .expect("Failed to call call_false");
    let coro_ptr_false = hdl_res_false as *mut IfaCoroutine;
    assert!(!coro_ptr_false.is_null());

    unsafe {
        let frame = ifa_rt_coro_frame(coro_ptr_false);
        // Step 1: YieldValue 99
        let s1 = ifa_rt_coro_resume(coro_ptr_false);
        assert_eq!(s1, 0, "Should suspend at else yield");
        let val1 = *(frame.add(8) as *const i64);
        assert_eq!(val1, 99, "Else yield value must be 99");

        // Step 2: Merge Return 99 + 1 = 100
        let s2 = ifa_rt_coro_resume(coro_ptr_false);
        assert_eq!(s2, 1, "Should complete at return");
        let val2 = *(frame.add(8) as *const i64);
        assert_eq!(val2, 100, "Merged return value must be 100");
        assert_eq!(ifa_rt_coro_is_done(coro_ptr_false), 1);

        ifa_rt_coro_destroy(coro_ptr_false);
    }
}
