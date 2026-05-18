use crate::base64url::decode_base64url;
use crate::credman::CredmanApi;
pub use crate::openid4vp_models::*;
use crate::reporter::report_match_result;
use nanoserde::DeJson;
use std::borrow::Cow;

fn parse_protocol_request_data<'a>(
    pr: &'a ProtocolRequest,
) -> Result<Cow<'a, OpenId4VpData>, Box<dyn std::error::Error>> {
    if pr.protocol == "openid4vp-v1-signed" {
        log::debug!("Handling signed OpenID4VP request");
        let jws: &'a str = if let Some(data) = &pr.data {
            match data {
                ProtocolRequestData::String(s) => s,
                ProtocolRequestData::Object(obj) => {
                    if obj.request.is_empty() {
                        return Err("Missing 'request' field in signed data object".into());
                    }
                    &obj.request
                }
            }
        } else if !pr.request.is_empty() {
            &pr.request
        } else {
            return Err("Missing signed request data".into());
        };

        let parts: Vec<&str> = jws.split('.').collect();
        if parts.len() < 2 {
            log::error!("Invalid JWS parts");
            return Err("Invalid JWS".into());
        }

        let decoded = decode_base64url(parts[1])?;
        return Ok(Cow::Owned(DeJson::deserialize_json(std::str::from_utf8(
            &decoded,
        )?)?));
    }

    log::debug!("Handling unsigned OpenID4VP request");
    if let Some(data) = &pr.data {
        return match data {
            ProtocolRequestData::Object(obj) => Ok(Cow::Borrowed(obj)),
            ProtocolRequestData::String(s) => Ok(Cow::Owned(DeJson::deserialize_json(s)?)),
        };
    }

    if !pr.request.is_empty() {
        return Ok(Cow::Owned(DeJson::deserialize_json(&pr.request)?));
    }

    Err("Missing unsigned request data".into())
}

pub fn openid4vp_main(credman: &mut impl CredmanApi) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Starting OpenID4VP matching process");
    let matcher_data_buffer = credman.get_registered_data();
    if matcher_data_buffer.len() < 4 {
        log::error!(
            "Matcher data buffer is too small: {}",
            matcher_data_buffer.len()
        );
        return Err("Matcher data too small".into());
    }

    let json_start = u32::from_le_bytes(matcher_data_buffer[..4].try_into()?);
    log::debug!("Registry JSON starts at offset: {}", json_start);
    let matcher_data_str = std::str::from_utf8(&matcher_data_buffer[json_start as usize..])?;
    log::debug!("Registry JSON: {}", matcher_data_str);
    let registry: Registry = match DeJson::deserialize_json(matcher_data_str) {
        Ok(data) => data,
        Err(e) => {
            log::error!(
                "Failed to deserialize registry: {:?}. JSON snippet: {}",
                e,
                &matcher_data_str[..std::cmp::min(100, matcher_data_str.len())]
            );
            return Err(e.into());
        }
    };
    log::info!("Successfully parsed registry");

    let request_buffer = credman.get_request_buffer();
    let request_str = std::str::from_utf8(&request_buffer)?;
    log::debug!("Request JSON: {}", request_str);
    let request: OpenId4VpRequest = match DeJson::deserialize_json(request_str) {
        Ok(req) => req,
        Err(e) => {
            log::error!(
                "Failed to deserialize request: {:?}. JSON: {}",
                e,
                request_str
            );
            return Err(e.into());
        }
    };

    let protocol_requests = if !request.requests.is_empty() {
        request.requests
    } else {
        request.providers
    };
    log::info!("Found {} protocol requests", protocol_requests.len());

    for (i, pr) in protocol_requests.iter().enumerate() {
        log::debug!("Processing request {}: protocol={}", i, pr.protocol);
        if pr.protocol != "openid4vp-v1-unsigned" && pr.protocol != "openid4vp-v1-signed" {
            log::warn!("Unsupported protocol: {}", pr.protocol);
            continue;
        }

        let data_json = parse_protocol_request_data(pr)?;
        let query = data_json.dcql_query.as_ref().ok_or("Missing dcql_query")?;
        let match_result = crate::dcql::dcql_query(query, &registry);

        report_match_result(credman, &match_result, i, &data_json, &matcher_data_buffer)?;
    }

    log::info!("OpenID4VP matching process completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_protocol_request_data_unsigned() {
        let pr = ProtocolRequest {
            protocol: "openid4vp-v1-unsigned".to_string(),
            data: Some(ProtocolRequestData::String(
                r#"{"request":"test"}"#.to_string(),
            )),
            request: "".to_string(),
        };
        let data = parse_protocol_request_data(&pr).unwrap();
        assert_eq!(data.request, "test");
    }

    #[test]
    fn test_parse_protocol_request_data_invalid_jws() {
        let pr = ProtocolRequest {
            protocol: "openid4vp-v1-signed".to_string(),
            data: Some(ProtocolRequestData::String("invalid.jws!".to_string())),
            request: "".to_string(),
        };
        let err = parse_protocol_request_data(&pr).unwrap_err();
        assert!(err.to_string().contains("Invalid character"));
    }

    #[test]
    fn test_parse_protocol_request_data_missing_data() {
        let pr = ProtocolRequest {
            protocol: "openid4vp-v1-unsigned".to_string(),
            data: None,
            request: "".to_string(),
        };
        let err = parse_protocol_request_data(&pr).unwrap_err();
        assert!(err.to_string().contains("Missing unsigned request data"));
    }
}
