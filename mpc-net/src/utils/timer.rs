// This part comes from ark. Add a few tweaks to accommodate to multithread environment.
// The indent still don't quite work for multithread environment. In fact I'm not sure how such thing can be illustrated linearly in multithread environment.
pub use colored::Colorize;

use std::cmp::min;
// print-trace requires std, so these imports are well-defined
pub use std::{
    format, println,
    string::{String, ToString},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::Instant,
};

pub static NUM_INDENT: AtomicUsize = AtomicUsize::new(0);
pub const PAD_CHAR: &str = "·";

pub struct TimerInfo {
    pub msg: String,
    pub time: Instant,
    pub print: bool,
    pub indent: usize,
}

#[cfg(not(feature = "report"))]
#[macro_export]
macro_rules! start_timer {
    ($msg:expr) => {{
        start_timer!($msg, true)
    }};
    ($msg:expr, $print:expr) => {{
        use $crate::utils::timer::{
            compute_indent, thread, Colorize, Instant, Ordering, ToString, NUM_INDENT,
        };

        let msg = $msg;
        if !$print {
            $crate::utils::timer::TimerInfo {
                msg: msg.to_string(),
                time: Instant::now(),
                print: $print,
                indent: 0,
            }
        } else {
            let start_info = "Start:".yellow().bold();
            let indent_amount = NUM_INDENT.fetch_add(1, Ordering::Relaxed);
            let indent = compute_indent(indent_amount);

            let msg = format!("{} (thread {:?})", &msg, thread::current().id());

            println!("{}{:8} {}", indent, start_info, msg);
            $crate::utils::timer::TimerInfo {
                msg: msg.to_string(),
                time: Instant::now(),
                print: $print,
                indent: indent_amount
            }
        }
    }};
}

#[cfg(feature = "report")]
#[macro_export]
macro_rules! start_timer {
    ($msg:expr) => {{
        start_timer!($msg, true)
    }};
    ($msg:expr, $print:expr) => {{
        use $crate::utils::timer::{
            compute_indent, thread, Colorize, Instant, Ordering, ToString, NUM_INDENT,
        };

        let msg = $msg;
        let start_info = "Start:".yellow().bold();
        let indent_amount = NUM_INDENT.fetch_add(1, Ordering::Relaxed);
        let indent = compute_indent(indent_amount);

        let msg = format!("{} (thread {:?})", &msg, thread::current().id());

        println!("{}{:8} {}", indent, start_info, msg);
        $crate::utils::timer::TimerInfo {
            msg: msg.to_string(),
            time: Instant::now(),
            print: $print,
            indent: indent_amount,
        }
    }};
}

#[cfg(not(feature = "report"))]
#[macro_export]
macro_rules! end_timer {
    ($time:expr) => {{
        end_timer!($time, "")
    }};
    ($time:expr, $msg:expr) => {{
        use $crate::utils::timer::{compute_indent, format, Colorize, Ordering, NUM_INDENT};

        let time = $time.time;
        let final_time = time.elapsed();
        if $time.print {
            let final_time_str = {
                let secs = final_time.as_secs();
                let millis = final_time.subsec_millis();
                let micros = final_time.subsec_micros() % 1000;
                let nanos = final_time.subsec_nanos() % 1000;
                if secs != 0 {
                    format!("{}.{:03}s", secs, millis).bold()
                } else if millis > 0 {
                    format!("{}.{:03}ms", millis, micros).bold()
                } else if micros > 0 {
                    format!("{}.{:03}µs", micros, nanos).bold()
                } else {
                    format!("{}ns", final_time.subsec_nanos()).bold()
                }
            };

            let end_info = "End:".green().bold();
            let message = format!("{} {}", $time.msg, $msg);
            NUM_INDENT.fetch_sub(1, Ordering::Relaxed);
            let indent_amount = $time.indent;
            let indent = compute_indent(indent_amount);

            // Todo: Recursively ensure that *entire* string is of appropriate
            // width (not just message).
            println!(
                "{}{:8} {:.<pad$}{}",
                indent,
                end_info,
                message,
                final_time_str,
                pad = 5
            );
        }
        final_time
    }};
}

#[cfg(feature = "report")]
#[macro_export]
macro_rules! end_timer {
    ($time:expr) => {{
        end_timer!($time, "")
    }};
    ($time:expr, $msg:expr) => {{
        use $crate::utils::timer::{compute_indent, format, Colorize, Ordering, NUM_INDENT};

        let time = $time.time;
        let final_time = time.elapsed();
        let final_time_str = {
            let secs = final_time.as_secs();
            let millis = final_time.subsec_millis();
            let micros = final_time.subsec_micros() % 1000;
            let nanos = final_time.subsec_nanos() % 1000;
            if secs != 0 {
                format!("{}.{:03}s", secs, millis).bold()
            } else if millis > 0 {
                format!("{}.{:03}ms", millis, micros).bold()
            } else if micros > 0 {
                format!("{}.{:03}µs", micros, nanos).bold()
            } else {
                format!("{}ns", final_time.subsec_nanos()).bold()
            }
        };

        let end_info = "End:".green().bold();
        let message = format!("{} {}", $time.msg, $msg);
        NUM_INDENT.fetch_sub(1, Ordering::Relaxed);
        let indent_amount = $time.indent;
        let indent = compute_indent(indent_amount);

        // Todo: Recursively ensure that *entire* string is of appropriate
        // width (not just message).
        println!(
            "{}{:8} {:.<pad$}{}",
            indent,
            end_info,
            message,
            final_time_str,
            pad = 5
        );
        final_time
    }};
}

#[macro_export]
macro_rules! timed {
    ($desc:expr, $e:expr) => {{
        timed!($desc, $e, true)
    }};
    ($desc:expr, $e:expr, $print:expr) => {{
        let timer = start_timer!($desc, $print);
        let result = { $e };
        end_timer!(timer);
        result
    }};
}

pub fn compute_indent_whitespace(indent_amount: usize) -> String {
    let mut indent = String::new();
    for _ in 0..indent_amount {
        indent.push_str(" ");
    }
    indent
}

pub fn compute_indent(indent_amount: usize) -> String {
    let indent_amount = min(6, indent_amount);
    let mut indent = String::new();
    for _ in 0..indent_amount {
        indent.push_str(&PAD_CHAR.white());
    }
    indent
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[test]
    fn should_print() {
        let timer = start_timer!("should_print1", false);
        let timer2 = start_timer!("should_print2", false);
        end_timer!(timer2);
        end_timer!(timer);
    }

    #[test]
    fn should_not_print() {
        let timer = start_timer!("should_print1", false);
        let timer2 = start_timer!("should_not_print2", true);
        end_timer!(timer2);
        end_timer!(timer);
    }

    #[test]
    fn should_identify_threadid() {
        println!("{:?}", std::thread::current().id());
    }

    #[test]
    fn timed_block() {
        timed!(
            "The answer to the universe",
            std::thread::sleep(Duration::from_millis(100))
        );
        let result = timed!("test", {
            std::thread::sleep(Duration::from_millis(100));
            42
        });
        println!("{}", result);
    }
}
