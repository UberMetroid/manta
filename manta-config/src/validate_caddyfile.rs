//! Caddyfile syntax, brace balance, comment-stripping, and per-host CrowdSec/AppSec/HSTS/Swagger validator.

const CLOUDFLARE_IPS: &str = include_str!("../../assets/cloudflare-ips.txt");

#[derive(Debug, PartialEq, Eq)]
pub struct ValidationReport {
    pub trusted_proxy_count: usize,
    pub site_count: usize,
    pub has_crowdsec: bool,
    pub has_appsec: bool,
    pub has_security_headers: bool,
    pub has_swagger_block: bool,
}

pub fn cloudflare_cidrs() -> Vec<&'static str> {
    CLOUDFLARE_IPS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

pub fn strip_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    for raw_line in content.lines() {
        if raw_line.trim().starts_with('#') {
            out.push('\n');
            continue;
        }
        let mut in_quotes = false;
        let mut escaped = false;
        for ch in raw_line.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' && in_quotes {
                out.push(ch);
                escaped = true;
            } else if ch == '"' {
                in_quotes = !in_quotes;
                out.push(ch);
            } else if !in_quotes && ch == '#' {
                break;
            } else {
                out.push(ch);
            }
        }
        out.push('\n');
    }
    out
}

pub fn check_balanced_braces(clean: &str) -> Result<Vec<(String, String)>, String> {
    let mut depth: i32 = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut blocks: Vec<(String, String)> = Vec::new();
    let mut cur_header = String::new();
    let mut cur_body = String::new();

    for (line_idx, raw_line) in clean.lines().enumerate() {
        for ch in raw_line.chars() {
            let target = if depth == 0 {
                &mut cur_header
            } else {
                &mut cur_body
            };
            if escaped {
                target.push(ch);
                escaped = false;
            } else if ch == '\\' && in_quotes {
                target.push(ch);
                escaped = true;
            } else if ch == '"' {
                in_quotes = !in_quotes;
                target.push(ch);
            } else if !in_quotes && ch == '{' {
                depth = depth.saturating_add(1);
                if depth > 1 {
                    cur_body.push(ch);
                }
            } else if !in_quotes && ch == '}' {
                depth = depth.saturating_sub(1);
                if depth < 0 {
                    return Err(format!("Unmatched '}}' at line {}", line_idx + 1));
                }
                if depth == 0 {
                    blocks.push((cur_header.trim().to_string(), cur_body.clone()));
                    cur_header.clear();
                    cur_body.clear();
                } else {
                    cur_body.push(ch);
                }
            } else {
                target.push(ch);
            }
        }
        if depth == 0 {
            cur_header.push('\n');
        } else {
            cur_body.push('\n');
        }
    }

    if in_quotes {
        return Err("Unclosed quotation mark in Caddyfile".to_string());
    }
    if depth != 0 {
        return Err(format!("Unbalanced braces in Caddyfile (depth: {depth})"));
    }
    Ok(blocks)
}

pub fn verify_security_directives(raw_content: &str) -> Result<ValidationReport, String> {
    let clean = strip_comments(raw_content);
    let blocks = check_balanced_braces(&clean)?;

    let global_body = blocks
        .iter()
        .find(|(h, _)| h.is_empty())
        .map(|(_, b)| b.as_str())
        .ok_or_else(|| "Missing global options block '{ ... }' in Caddyfile".to_string())?;

    if !global_body.contains("order crowdsec first")
        || !global_body.contains("order appsec after crowdsec")
    {
        return Err(
            "Global options block missing 'order crowdsec first' or 'order appsec after crowdsec'"
                .to_string(),
        );
    }
    if !global_body.contains("trusted_proxies static") || !global_body.contains("CF-Connecting-IP")
    {
        return Err(
            "Global servers block missing 'trusted_proxies static' or 'CF-Connecting-IP'"
                .to_string(),
        );
    }

    let required_cf = cloudflare_cidrs();
    for cidr in &required_cf {
        if !global_body.contains(cidr) {
            return Err(format!(
                "Global trusted_proxies missing Cloudflare CIDR: {cidr}"
            ));
        }
    }

    let has_sec_snippet = blocks.iter().any(|(h, b)| {
        h == "(security_headers)"
            && b.contains("Strict-Transport-Security")
            && b.contains("X-Content-Type-Options")
            && b.contains("nosniff")
            && b.contains("X-Frame-Options")
            && b.contains("SAMEORIGIN")
            && b.contains("-Server")
    });

    let site_blocks: Vec<&(String, String)> = blocks
        .iter()
        .filter(|(h, _)| !h.is_empty() && !h.starts_with('('))
        .collect();
    if site_blocks.is_empty() {
        return Err("Caddyfile contains zero virtual host site blocks".to_string());
    }

    for (site_hdr, site_body) in &site_blocks {
        if !site_body.lines().any(|l| l.trim() == "crowdsec") {
            return Err(format!(
                "Site '{site_hdr}' missing 'crowdsec' bouncer directive"
            ));
        }
        if !site_body
            .lines()
            .any(|l| l.trim() == "appsec" || l.trim().starts_with("appsec "))
        {
            return Err(format!("Site '{site_hdr}' missing 'appsec' WAF directive"));
        }
        let site_has_headers = (has_sec_snippet
            && site_body
                .lines()
                .any(|l| l.trim() == "import security_headers"))
            || (site_body
                .lines()
                .any(|l| l.trim().starts_with("Strict-Transport-Security"))
                && site_body.lines().any(|l| {
                    l.trim().starts_with("X-Content-Type-Options") && l.contains("nosniff")
                })
                && site_body
                    .lines()
                    .any(|l| l.trim().starts_with("X-Frame-Options") && l.contains("SAMEORIGIN"))
                && site_body.lines().any(|l| l.trim() == "-Server"));
        if !site_has_headers {
            return Err(format!(
                "Site '{site_hdr}' missing required security headers"
            ));
        }
        let site_has_swagger = site_body.lines().any(|l| {
            let t = l.trim();
            t.starts_with("path ")
                && t.contains("/swagger*")
                && t.contains("/api-docs*")
                && t.contains("/openapi*")
        }) && site_body
            .lines()
            .any(|l| l.trim().starts_with("respond ") && l.trim().ends_with(" 403"));
        if !site_has_swagger {
            return Err(format!(
                "Site '{site_hdr}' missing '/swagger*', '/api-docs*', and '/openapi*' 403 block"
            ));
        }
    }

    Ok(ValidationReport {
        trusted_proxy_count: required_cf.len(),
        site_count: site_blocks.len(),
        has_crowdsec: !site_blocks.is_empty(),
        has_appsec: !site_blocks.is_empty(),
        has_security_headers: !site_blocks.is_empty(),
        has_swagger_block: !site_blocks.is_empty(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const DEFAULT_TEMPLATE: &str = include_str!("../../assets/default-Caddyfile");

    #[test]
    fn test_validate_default_template_and_reject_comment_spoofing() {
        let cf = cloudflare_cidrs().join(" ");
        let rendered = DEFAULT_TEMPLATE
            .replace("__TRUSTED_PROXIES__", &format!("127.0.0.1/32 {cf}"))
            .replace("__CROWDSEC_URL__", "http://172.17.0.1:8091")
            .replace("__APPSEC_URL__", "http://172.17.0.1:7422")
            .replace("__EMBY_DOMAIN__", "http://green.clownhouse.io")
            .replace("__EMBY_UPSTREAM__", "172.17.0.1:9096")
            .replace("__JELLYFIN_DOMAIN__", "http://purple.clownhouse.io")
            .replace("__JELLYFIN_UPSTREAM__", "172.17.0.1:8096")
            .replace("__SEERR_DOMAIN__", "http://oracle.clownhouse.io")
            .replace("__SEERR_UPSTREAM__", "172.17.0.1:5055");

        let report = verify_security_directives(&rendered).unwrap();
        assert_eq!(report.trusted_proxy_count, 22);
        assert_eq!(report.site_count, 3);

        let stripped_waf = rendered.replace("\tcrowdsec\n", "\t# crowdsec\n");
        assert!(verify_security_directives(&stripped_waf).is_err());
    }
}
