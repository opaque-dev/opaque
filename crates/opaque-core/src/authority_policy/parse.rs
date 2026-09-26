use serde_json::{Map, Value};
use yaml_rust2::{
    parser::{Event, Parser},
    scanner::TScalarStyle,
};
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 4096;

pub(super) fn document(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > super::MAX_BYTES {
        return Err("policy input exceeds byte limit".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "policy must be UTF-8")?;
    let mut parser = Parser::new_from_str(text);
    expect(&mut parser, Event::StreamStart)?;
    expect(&mut parser, Event::DocumentStart)?;
    let mut nodes = 0;
    let value = node(&mut parser, 0, &mut nodes)?;
    expect(&mut parser, Event::DocumentEnd)?;
    expect(&mut parser, Event::StreamEnd)?;
    Ok(value)
}
fn next(parser: &mut Parser<std::str::Chars<'_>>) -> Result<Event, String> {
    parser
        .next_token()
        .map(|(event, _)| event)
        .map_err(|_| "invalid YAML or JSON policy".into())
}
fn expect(parser: &mut Parser<std::str::Chars<'_>>, expected: Event) -> Result<(), String> {
    if next(parser)? != expected {
        return Err("policy requires exactly one complete document".into());
    }
    Ok(())
}
fn node(
    parser: &mut Parser<std::str::Chars<'_>>,
    depth: usize,
    nodes: &mut usize,
) -> Result<Value, String> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err("policy structure exceeds limits".into());
    }
    match next(parser)? {
        Event::Scalar(s, style, 0, None) => {
            if style == TScalarStyle::Plain {
                // The supported scalar profile uses JSON booleans/numbers/null;
                // enum values and references remain strings, never YAML objects.
                if let Ok(value) = serde_json::from_str::<Value>(&s)
                    && !value.is_array()
                    && !value.is_object()
                {
                    return Ok(value);
                }
            }
            Ok(Value::String(s))
        }
        Event::SequenceStart(0, None) => {
            let mut values = Vec::new();
            while parser.peek().map_err(|_| "invalid YAML sequence")?.0 != Event::SequenceEnd {
                values.push(node(parser, depth + 1, nodes)?);
            }
            expect(parser, Event::SequenceEnd)?;
            Ok(Value::Array(values))
        }
        Event::MappingStart(0, None) => {
            let mut values = Map::new();
            while parser.peek().map_err(|_| "invalid YAML mapping")?.0 != Event::MappingEnd {
                let Value::String(key) = node(parser, depth + 1, nodes)? else {
                    return Err("policy mapping keys must be strings".into());
                };
                if key == "<<" || values.contains_key(&key) {
                    return Err("duplicate or merge policy key".into());
                }
                values.insert(key, node(parser, depth + 1, nodes)?);
            }
            expect(parser, Event::MappingEnd)?;
            Ok(Value::Object(values))
        }
        _ => Err("policy aliases, anchors, tags and complex keys are unsupported".into()),
    }
}
