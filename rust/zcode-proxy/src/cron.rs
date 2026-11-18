//! Numeric five-field cron parsing and bounded next-run display calculation.

use chrono::{DateTime, Datelike, Duration, Local, LocalResult, TimeZone, Timelike};

struct Field {
    values: u64,
    star: bool,
}

impl Field {
    fn parse(text: &str, min: u32, max: u32) -> Result<Self, &'static str> {
        let mut values = 0u64;
        for part in text.split(',') {
            let (range, step) = match part.split_once('/') {
                Some((range, step)) => {
                    let step = step.parse::<i64>().map_err(|_| "invalid cron step")?;
                    if step <= 0 {
                        return Err("invalid cron step");
                    }
                    (range, step as u64)
                }
                None => (part, 1),
            };
            let number = |value: &str| -> Result<u32, &'static str> {
                let value = value.parse::<u32>().map_err(|_| "invalid cron number")?;
                if !(min..=max).contains(&value) {
                    return Err("cron value out of range");
                }
                Ok(value)
            };
            let (start, end) = if range == "*" {
                (min, max)
            } else if let Some((start, end)) = range.split_once('-') {
                (number(start)?, number(end)?)
            } else {
                let start = number(range)?;
                (start, if part.contains('/') { max } else { start })
            };
            if start > end {
                return Err("invalid cron range");
            }
            for value in start..=end {
                if u64::from(value - start) % step == 0 {
                    values |= 1u64 << value;
                }
            }
        }
        Ok(Self {
            values,
            star: text == "*" || text.starts_with("*/") || text.split(',').any(|p| p == "*"),
        })
    }

    fn matches(&self, value: u32) -> bool {
        self.values & (1u64 << value) != 0
    }
}

pub(crate) struct Cron {
    minute: Field,
    hour: Field,
    day: Field,
    month: Field,
    weekday: Field,
}

impl Cron {
    pub(crate) fn parse(expression: &str) -> Result<Self, &'static str> {
        let fields: Vec<_> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err("cron expression must have five fields");
        }
        Ok(Self {
            minute: Field::parse(fields[0], 0, 59)?,
            hour: Field::parse(fields[1], 0, 23)?,
            day: Field::parse(fields[2], 1, 31)?,
            month: Field::parse(fields[3], 1, 12)?,
            weekday: Field::parse(fields[4], 0, 6)?,
        })
    }

    pub(crate) fn next_run(&self, from: DateTime<Local>) -> Option<String> {
        let start = from.with_second(0)?.with_nanosecond(0)? + Duration::minutes(1);
        let limit = start + Duration::days(366);
        let mut date = start.date_naive();
        // Skip nonmatching dates rather than examining half a million minutes for impossible dates.
        while date <= limit.date_naive() {
            let day = self.day.matches(date.day());
            let weekday = self.weekday.matches(date.weekday().num_days_from_sunday());
            let day_matches = if !self.day.star && !self.weekday.star {
                day || weekday
            } else {
                day && weekday
            };
            if self.month.matches(date.month()) && day_matches {
                let mut earliest = None;
                for hour in 0..24 {
                    if !self.hour.matches(hour) {
                        continue;
                    }
                    for minute in 0..60 {
                        if !self.minute.matches(minute) {
                            continue;
                        }
                        let wall_time = date.and_hms_opt(hour, minute, 0)?;
                        let candidates = match Local.from_local_datetime(&wall_time) {
                            LocalResult::Single(t) => [Some(t), None],
                            LocalResult::Ambiguous(a, b) => [Some(a), Some(b)],
                            LocalResult::None => [None, None],
                        };
                        for t in candidates.into_iter().flatten() {
                            if t >= start && t < limit && earliest.is_none_or(|old| t < old) {
                                earliest = Some(t);
                            }
                        }
                    }
                }
                if let Some(t) = earliest {
                    return Some(t.format("%Y-%m-%d %H:%M").to_string());
                }
            }
            date = date.succ_opt()?;
        }
        None
    }
}
