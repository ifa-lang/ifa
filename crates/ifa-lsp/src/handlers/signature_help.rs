//! Signature Help provider (LSP 3.17) for active function parameters.

use crate::document::Document;
use crate::protocol::{
    MarkupContent, ParameterInformation, Position, SignatureHelp, SignatureInformation,
};
use ifa_span::sym;

/// Handle `textDocument/signatureHelp` request.
pub fn handle_signature_help(doc: &Document, position: Position) -> Option<SignatureHelp> {
    let analysis = doc.analysis.as_ref()?;
    let offset = doc.position_to_offset(position);
    let bytes = doc.text.as_bytes();

    if offset == 0 || offset > bytes.len() {
        return None;
    }

    // Scan backwards from cursor to find opening '(' and count active argument index (commas)
    let mut idx = offset;
    let mut paren_depth: usize = 0;
    let mut comma_count: u32 = 0;
    let mut call_open_idx: Option<usize> = None;

    while idx > 0 {
        idx -= 1;
        let b = bytes[idx];

        if b == b')' {
            paren_depth += 1;
        } else if b == b'(' {
            if paren_depth > 0 {
                paren_depth -= 1;
            } else {
                call_open_idx = Some(idx);
                break;
            }
        } else if b == b',' && paren_depth == 0 {
            comma_count += 1;
        } else if b == b';' || b == b'{' || b == b'}' {
            // Hit statement or block delimiter without finding open paren
            break;
        }
    }

    let paren_pos = call_open_idx?;

    // Scan backwards from paren_pos to extract function identifier
    let mut fn_end = paren_pos;
    while fn_end > 0 && (bytes[fn_end - 1] == b' ' || bytes[fn_end - 1] == b'\t') {
        fn_end -= 1;
    }

    let mut fn_start = fn_end;
    while fn_start > 0
        && (bytes[fn_start - 1].is_ascii_alphanumeric() || bytes[fn_start - 1] == b'_')
    {
        fn_start -= 1;
    }

    if fn_start >= fn_end {
        return None;
    }

    let fn_name = std::str::from_utf8(&bytes[fn_start..fn_end]).ok()?;
    let fn_symbol = sym(fn_name);

    let func = analysis.symbols.functions.get(&fn_symbol)?;

    let mut param_infos = Vec::new();
    let mut param_strings = Vec::new();

    for p in &func.params {
        let p_name = p.name.resolve();
        let p_label = format!("{}: {}", p_name, p.ty);
        param_strings.push(p_label.clone());
        param_infos.push(ParameterInformation {
            label: p_label,
            documentation: Some(MarkupContent::markdown(format!(
                "Parameter `{}` of type `{}`",
                p_name, p.ty
            ))),
        });
    }

    let sig_label = format!(
        "fn {}({}) -> {}",
        fn_name,
        param_strings.join(", "),
        func.ret_ty
    );

    let active_param = if func.params.is_empty() {
        None
    } else {
        Some(comma_count.min((func.params.len() - 1) as u32))
    };

    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: sig_label.clone(),
            documentation: Some(MarkupContent::markdown(format!(
                "```ifa\n{}\n```",
                sig_label
            ))),
            parameters: param_infos,
            active_parameter: active_param,
        }],
        active_signature: Some(0),
        active_parameter: active_param,
    })
}
