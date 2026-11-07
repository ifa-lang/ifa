use crate::error::CodegenError;
use cranelift_codegen::ir::{types, AbiParam, Signature};
use cranelift_codegen::isa::CallConv;
use ifa_fir::{FirFunction, FirType};
use ifa_sema::types::{FloatType, IntType};

/// Convert FIR type into corresponding Cranelift IR type.
pub fn fir_type_to_cranelift(ty: &FirType, ptr_type: types::Type) -> Option<types::Type> {
    match ty {
        FirType::Unit => None,
        FirType::Bool => Some(types::I8),
        FirType::Int(int_ty) => match int_ty {
            IntType::I8 | IntType::U8 => Some(types::I8),
            IntType::I16 | IntType::U16 => Some(types::I16),
            IntType::I32 | IntType::U32 => Some(types::I32),
            IntType::I64 | IntType::U64 | IntType::ISize | IntType::USize => Some(types::I64),
        },
        FirType::Float(float_ty) => match float_ty {
            FloatType::F32 => Some(types::F32),
            FloatType::F64 => Some(types::F64),
        },
        FirType::Char => Some(types::I32),
        FirType::Str
        | FirType::String
        | FirType::Pointer(_)
        | FirType::GenerationalRef(_)
        | FirType::Channel(_)
        | FirType::Struct(_, _)
        | FirType::Array(_, _)
        | FirType::Range { .. }
        | FirType::Slice(_) => Some(ptr_type),
        FirType::Optional(inner) => fir_type_to_cranelift(inner, ptr_type),
        FirType::ErrorUnion { .. } => Some(ptr_type),
        FirType::Function { .. } => Some(ptr_type),
        FirType::Enum(_, vars) => {
            let has_payload = vars.iter().any(|(_, opt)| opt.is_some());
            if has_payload {
                Some(ptr_type)
            } else {
                Some(types::I64)
            }
        }
    }
}

/// Build a Cranelift function signature from a FIR function declaration.
pub fn fir_signature_to_cranelift(
    func: &FirFunction,
    call_conv: CallConv,
    ptr_type: types::Type,
) -> Result<Signature, CodegenError> {
    let mut sig = Signature::new(call_conv);

    // Map parameters
    for param in &func.params {
        let cl_type = if param.mode == ifa_ast::ParamMode::InOut {
            ptr_type
        } else {
            fir_type_to_cranelift(&param.ty, ptr_type).unwrap_or(ptr_type)
        };
        sig.params.push(AbiParam::new(cl_type));
    }

    // Map return type
    let fn_name = ifa_span::INTERNER.resolve(&func.name);
    if let Some(ret_type) = fir_type_to_cranelift(&func.ret_ty, ptr_type) {
        sig.returns.push(AbiParam::new(ret_type));
    } else if fn_name == "main" {
        // Native host ABI requires main to return an integer exit status
        sig.returns.push(AbiParam::new(types::I32));
    }

    Ok(sig)
}

/// Calculate the byte size of a FIR type for native allocation.
pub fn fir_type_byte_size(ty: &FirType) -> usize {
    match ty {
        FirType::Unit => 0,
        FirType::Bool | FirType::Int(IntType::I8 | IntType::U8) => 1,
        FirType::Int(IntType::I16 | IntType::U16) => 2,
        FirType::Int(IntType::I32 | IntType::U32)
        | FirType::Float(FloatType::F32)
        | FirType::Char => 4,
        FirType::Enum(_, vars) => {
            let has_payload = vars.iter().any(|(_, opt)| opt.is_some());
            if has_payload {
                16
            } else {
                8
            }
        }
        FirType::Int(IntType::I64 | IntType::U64 | IntType::ISize | IntType::USize)
        | FirType::Float(FloatType::F64)
        | FirType::Str
        | FirType::String
        | FirType::Pointer(_)
        | FirType::GenerationalRef(_)
        | FirType::Channel(_)
        | FirType::Slice(_)
        | FirType::Function { .. } => 8,
        FirType::Range { elem, .. } => fir_type_byte_size(elem) * 2 + 8,
        FirType::Array(elem_ty, len) => fir_type_byte_size(elem_ty) * (*len as usize),
        FirType::Struct(_, fields) => fields
            .iter()
            .map(|f| fir_type_byte_size(&f.1).max(8))
            .sum::<usize>()
            .max(8),
        FirType::Optional(inner) => fir_type_byte_size(inner) + 1,
        FirType::ErrorUnion { ok, .. } => fir_type_byte_size(ok) + 8,
    }
}
