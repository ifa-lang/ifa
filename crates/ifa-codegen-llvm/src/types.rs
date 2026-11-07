use crate::error::LlvmCodegenError;
use ifa_fir::FirType;
use ifa_sema::types::{FloatType, IntType};
use ifa_span::INTERNER;

/// Map a FIR intermediate type to its canonical LLVM IR type string.
pub fn fir_to_llvm_type(ty: &FirType) -> Result<String, LlvmCodegenError> {
    match ty {
        FirType::Unit => Ok("void".to_string()),
        FirType::Bool => Ok("i1".to_string()),
        FirType::Int(int_ty) => match int_ty {
            IntType::I8 | IntType::U8 => Ok("i8".to_string()),
            IntType::I16 | IntType::U16 => Ok("i16".to_string()),
            IntType::I32 | IntType::U32 => Ok("i32".to_string()),
            IntType::I64 | IntType::U64 | IntType::ISize | IntType::USize => Ok("i64".to_string()),
        },
        FirType::Float(float_ty) => match float_ty {
            FloatType::F32 => Ok("float".to_string()),
            FloatType::F64 => Ok("double".to_string()),
        },
        FirType::Char => Ok("i8".to_string()),
        FirType::Str | FirType::String => Ok("ptr".to_string()),
        FirType::Pointer(_) => Ok("ptr".to_string()),
        FirType::GenerationalRef(_) => Ok("{ ptr, i32, i16, i16 }".to_string()),
        FirType::Struct(sym, _) => {
            let name = INTERNER.resolve(sym);
            Ok(format!("%struct.{}", name))
        }
        FirType::Array(elem_ty, count) => {
            let inner = fir_to_llvm_type(elem_ty)?;
            Ok(format!("[{} x {}]", count, inner))
        }
        FirType::Slice(_) => Ok("{ ptr, i64 }".to_string()),
        FirType::Optional(elem) => {
            let inner = fir_to_llvm_type(elem)?;
            Ok(format!("{{ i1, {} }}", inner))
        }
        FirType::ErrorUnion { .. } => Ok("ptr".to_string()),
        FirType::Enum(sym, _) => {
            let name = INTERNER.resolve(sym);
            Ok(format!("%enum.{}", name))
        }
        FirType::Function { .. } => Ok("ptr".to_string()),
    }
}
