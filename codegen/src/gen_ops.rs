use std::fmt::Write;

use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

use crate::{
    gen_attrs::{gen_attrset, shorthand_name},
    gen_iterable::iterable_name,
    gen_request_impl::{self, OpInfo, WrapperInfo},
    gen_utils::escape_md,
    gen_writable::{gen_writable_attrset, writable_func, writable_type},
    parse_spec::{AttrProp, AttrSet, AttrType, Operation, OperationSpec, Request, Spec},
    Context,
};

pub fn request_kebab_name(type_name: &str, op_name: &str) -> String {
    let delim = if type_name.is_empty() { "" } else { "-" };
    format!("op{delim}{type_name}-{op_name}")
}

pub fn reply_kebab_name(type_name: &str, op_name: &str) -> String {
    let delim = if type_name.is_empty() { "" } else { "-" };
    format!("op{delim}{type_name}-{op_name}-reply")
}

pub fn gen_ops(tokens: &mut TokenStream, spec: &Spec, ctx: &mut Context) {
    let mut request_names = Vec::new();

    for op in &spec.operations.list {
        gen_op(tokens, spec, ctx, op, &mut request_names);
    }

    if let Some(attrs) = &spec.operations.fallback_attrs {
        let ops = OperationSpec {
            name: "".into(),
            transparent: true,
            request_type_at_runtime: true,
            attribute_set: Some(attrs.clone()),
            r#do: Some(Operation::default()),
            dump: Some(Operation::default()),
            value: Some(0xfefe),
            fixed_header: if spec.is_genetlink() {
                None
            } else if let Some(fixed_header) = &spec.operations.fixed_header {
                Some(fixed_header.clone())
            } else {
                panic!(
                    "Netlink-raw specification specifies fallback-attrs, but not fixed-header. Likely an error"
                )
            },
            ..Default::default()
        };
        gen_op(tokens, spec, ctx, &ops, &mut request_names);
    }

    gen_request_impl::gen_request(tokens, ctx, spec, &request_names);
}

pub fn gen_op_header(
    op_header_value: &OpHeaderValue,
    header: &Ident,
    value_expr: Option<&TokenStream>,
) -> TokenStream {
    let OpHeaderValue {
        needs_value,
        cmd,
        version,
    } = &op_header_value;
    assert_eq!(*needs_value, value_expr.is_some());
    let default_value = quote!(#cmd);
    let value = value_expr.unwrap_or(&default_value);
    quote! {
        #header.cmd = #value;
        #header.version = #version;
    }
}

#[derive(Clone, Hash, PartialEq)]
pub struct OpHeader {
    pub name: String,
    pub op_header_value: Option<OpHeaderValue>,
}

#[derive(Clone, Hash, PartialEq)]
pub struct OpHeaderValue {
    needs_value: bool,
    cmd: u8,
    version: u8,
}

// TODO: enum model
fn whitelist_op_attrs(attrs: &mut Vec<AttrProp>, allowed: &[String]) {
    // request_attrs
    //     .attributes
    //     .retain(|a| op.request.attributes.contains(&a.name));
    for attr in attrs {
        if !allowed.contains(&attr.name) {
            attr.r#type = AttrType::Unused;
        }
    }
}

pub fn get_value(ops: &OperationSpec, op: &Request) -> u16 {
    let same_ptr = |l: &Request, r: &Request| l as *const _ == r as *const _;
    let is_request = |l: &Option<Operation>| l.as_ref().is_some_and(|o| same_ptr(&o.request, op));
    let is_reply = |l: &Option<Operation>| l.as_ref().is_some_and(|o| same_ptr(&o.reply, op));

    let is_request = if is_request(&ops.r#do) || is_request(&ops.dump) {
        true
    } else if is_reply(&ops.r#do) || is_reply(&ops.dump) {
        false
    } else {
        unreachable!()
    };

    let check_do_op = |check_request: bool| {
        let op = ops.r#do.as_ref()?;
        if check_request {
            op.request.value.as_ref()
        } else {
            op.reply.value.as_ref()
        }
    };

    let value = None
        .or(op.value.as_ref())
        .or(ops.value.as_ref())
        .or_else(|| check_do_op(is_request))
        .or_else(|| check_do_op(!is_request))
        .unwrap_or_else(|| panic!("Operation {:?} doesn't specify a value", ops.name));

    *value
}

pub fn gen_op(
    tokens: &mut TokenStream,
    spec: &Spec,
    ctx: &mut Context,
    ops: &OperationSpec,
    request_names: &mut Vec<OpInfo>,
) {
    let is_transparent = spec.operations.transparent || ops.transparent;
    let needs_value = ops.request_type_at_runtime;

    let fixed_header = |op: &Request| match (
        op.fixed_header.as_ref().or(ops.fixed_header.as_ref()),
        spec.protocol.as_deref(),
    ) {
        (Some(h), _) => Some(OpHeader {
            name: h.clone(),
            op_header_value: None,
        }),
        (None, Some("genetlink" | "genetlink-legacy")) => {
            let cmd = get_value(ops, op) as u8;
            // The expected use for genlmsghdr.version was to allow versioning of the
            // APIs provided by the subsystems.
            // From: https://docs.kernel.org/userspace-api/netlink/intro.html#generic-netlink
            let version: u8 = spec.version.unwrap_or(1);
            Some(OpHeader {
                name: "builtin-nfgenmsg".into(),
                op_header_value: Some(OpHeaderValue {
                    needs_value,
                    cmd,
                    version,
                }),
            })
        }
        _ => None,
    };

    let mut doc_str = String::new();
    if let Some(doc) = &ops.doc {
        writeln!(doc_str, "{}", escape_md(ctx, doc)).unwrap();
    }
    if !ops.flags.is_empty() {
        writeln!(doc_str, "Flags: {}", ops.flags.join(", ")).unwrap();
        writeln!(doc_str).unwrap();
    }

    let mut generate = |op_name: &str, op: &Operation| {
        let request_attrset = None
            .or(ops.attribute_set.as_ref())
            .or(op.request.attribute_set.as_ref())
            .unwrap();
        let request_attrs = spec.find_attr(request_attrset);
        let request_name = request_kebab_name(&ops.name, op_name);
        let mut request_attrs = AttrSet {
            name: request_name.clone(),
            subset_of: Some(request_attrs.name.clone()),
            ..request_attrs.clone()
        };
        if !spec.operations.all_attrs && !ops.all_attrs {
            whitelist_op_attrs(&mut request_attrs.attributes, &op.request.attributes);
        }

        let reply_attrset = None
            .or(ops.attribute_set.as_ref())
            .or(op.reply.attribute_set.as_ref())
            .unwrap();
        let reply_attrs = spec.find_attr(reply_attrset);
        let reply_header = fixed_header(&op.reply);
        let reply_name = reply_kebab_name(&ops.name, op_name);
        let mut reply_attrs = AttrSet {
            name: reply_name.clone(),
            subset_of: Some(reply_attrs.name.clone()),
            ..reply_attrs.clone()
        };
        if !spec.operations.all_attrs && !ops.all_attrs {
            whitelist_op_attrs(&mut reply_attrs.attributes, &op.reply.attributes);
        }

        // Document accepted attributes on a transparent operation wrapper
        let mut op_doc = None;
        if is_transparent {
            let mut doc_str = doc_str.clone();

            let req = writable_type(request_attrset);
            let reply = iterable_name(reply_attrset);

            let not_mute =
                |attr: &&AttrProp| !matches!(attr.r#type, AttrType::Unused | AttrType::Pad { .. });
            if request_attrs.attributes.iter().any(|m| not_mute(&m)) {
                writeln!(doc_str, "Request attributes:").unwrap();
                for attr in request_attrs.attributes.iter().filter(not_mute) {
                    for func in &writable_func(spec, &request_attrs, attr) {
                        writeln!(doc_str, "- [.{func}()]({req}::{func})").unwrap();
                        ctx.test_exprs
                            .insert(format!("let _ = {req}::<&mut Vec<u8>>::{func};"));
                    }
                }
                writeln!(doc_str).unwrap();
            }

            if reply_attrs.attributes.iter().any(|m| not_mute(&m)) {
                writeln!(doc_str, "Reply attributes:").unwrap();
                for attr in reply_attrs.attributes.iter().filter(not_mute) {
                    let func = shorthand_name(&attr.name);
                    writeln!(doc_str, "- [.{func}()]({reply}::{func})").unwrap();
                    ctx.test_exprs.insert(format!("let _ = {reply}::{func};"));
                }
                writeln!(doc_str).unwrap();
            }

            op_doc = Some(doc_str);
        }

        let request_header = || fixed_header(&op.request);
        request_names.push(OpInfo {
            name: request_name.clone(),
            header: request_header(),
            needs_value,
            no_ack: ops.no_ack,
            doc: op_doc,
        });
        let request_header = request_header();

        if !is_transparent {
            let mut doc = quote!();
            if !doc_str.is_empty() {
                doc = quote!(#[doc = #doc_str]);
            }

            tokens.extend(doc.clone());
            gen_writable_attrset(
                tokens,
                ctx,
                spec,
                &request_attrs,
                request_header.as_ref(),
                needs_value,
            );

            tokens.extend(doc.clone());
            gen_attrset(tokens, spec, ctx, &request_attrs, request_header.as_ref());

            tokens.extend(doc.clone());
            gen_writable_attrset(
                tokens,
                ctx,
                spec,
                &reply_attrs,
                reply_header.as_ref(),
                needs_value,
            );

            tokens.extend(doc.clone());
            gen_attrset(tokens, spec, ctx, &reply_attrs, reply_header.as_ref());
        }

        let info = WrapperInfo {
            is_dump: op_name == "dump",
            request_value: get_value(ops, &op.request),
            request_name,
            reply_name,
            request_header,
            reply_header,
            needs_value,
            transparent_attrs: is_transparent
                .then_some((request_attrset.as_str(), reply_attrset.as_str())),
            op_info: request_names.last().unwrap().clone(),
        };

        gen_request_impl::gen_request_wrapper(tokens, ctx, spec, &info);
    };

    if let Some(dump) = &ops.dump {
        generate("dump", dump);
    }

    if let Some(r#do) = &ops.r#do {
        generate("do", r#do);
    }
}
