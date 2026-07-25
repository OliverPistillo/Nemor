use crate::CollectorError;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PsiSample {
    pub some: Option<PsiLine>,
    pub full: Option<PsiLine>,
}

pub fn parse(resource: &'static str, input: &str) -> Result<PsiSample, CollectorError> {
    let mut some = None;
    let mut full = None;
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        let kind = parts
            .next()
            .ok_or_else(|| malformed(resource, "empty line"))?;
        if !matches!(kind, "some" | "full") {
            continue;
        }
        let mut avg10 = None;
        let mut avg60 = None;
        let mut avg300 = None;
        let mut total = None;
        for token in parts {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| malformed(resource, format!("invalid token `{token}`")))?;
            match key {
                "avg10" => avg10 = Some(parse_average(resource, key, value)?),
                "avg60" => avg60 = Some(parse_average(resource, key, value)?),
                "avg300" => avg300 = Some(parse_average(resource, key, value)?),
                "total" => {
                    total = Some(value.parse::<u64>().map_err(|error| {
                        malformed(resource, format!("invalid `total`: {error}"))
                    })?)
                }
                _ => {}
            }
        }
        let parsed = PsiLine {
            avg10: required(resource, "avg10", avg10)?,
            avg60: required(resource, "avg60", avg60)?,
            avg300: required(resource, "avg300", avg300)?,
            total_us: required(resource, "total", total)?,
        };
        match kind {
            "some" => some = Some(parsed),
            "full" => full = Some(parsed),
            _ => {}
        }
    }
    if some.is_none() {
        return Err(malformed(resource, "required `some` line is missing"));
    }
    Ok(PsiSample { some, full })
}

fn parse_average(resource: &'static str, key: &str, value: &str) -> Result<f64, CollectorError> {
    let parsed = value
        .parse::<f64>()
        .map_err(|error| malformed(resource, format!("invalid `{key}`: {error}")))?;
    if parsed.is_finite() && (0.0..=100.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(malformed(
            resource,
            format!("`{key}` must be finite and between 0 and 100"),
        ))
    }
}

fn required<T>(resource: &'static str, key: &str, value: Option<T>) -> Result<T, CollectorError> {
    value.ok_or_else(|| malformed(resource, format!("required `{key}` is missing")))
}

fn malformed(resource: &'static str, message: impl Into<String>) -> CollectorError {
    CollectorError::invalid(resource, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: &str = "some avg10=1.25 avg60=2.50 avg300=3.75 total=100\nfull avg10=0.25 avg60=0.50 avg300=0.75 total=10\n";

    #[test]
    fn parses_some_and_full_architecture_for_all_resources() {
        for resource in ["psi_memory", "psi_cpu", "psi_io"] {
            let value = parse(resource, BOTH).expect("PSI");
            assert_eq!(value.some.expect("some").avg10, 1.25);
            assert_eq!(value.full.expect("full").total_us, 10);
        }
    }

    #[test]
    fn full_is_optional() {
        let value = parse(
            "psi_cpu",
            "some avg10=0.00 avg60=0.01 avg300=0.02 total=3\n",
        )
        .expect("CPU PSI");
        assert!(value.full.is_none());
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(parse("psi_memory", "some avg10=x avg60=0 avg300=0 total=0\n").is_err());
        assert!(parse("psi_io", "full avg10=0 avg60=0 avg300=0 total=0\n").is_err());
    }
}
