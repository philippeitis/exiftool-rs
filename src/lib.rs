use std::io::{Read, Write};
use std::process::{Child, Stdio};
use std::str::FromStr;
use std::time::Duration;

use bstr::ByteSlice;
use serde_json::Value;
use tokio::sync::Mutex;

fn is_whitespace(c: &u8) -> bool {
    c == &b'\t' || c == &b' '
}

fn is_not_whitespace(c: &u8) -> bool {
    !is_whitespace(c)
}

fn trim_end(v: &mut Vec<u8>) {
    if let Some(first) = v.iter().rposition(is_not_whitespace) {
        v.truncate(first);
    } else {
        v.truncate(0);
    }
}

const SEQ_ERR_STATUS_DELIM: &str = "=";

async fn read_fd_ends_with<R: Read>(mut fd: R, seq_ready: &str, block_size: usize) -> Vec<u8> {
    let endswith_count = seq_ready.bytes().len() + 2;
    let mut output = Vec::new();
    let mut buf = vec![0; block_size];
    loop {
        match fd.read(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                output.extend_from_slice(&buf[..n]);
                if output[output.len().saturating_sub(endswith_count)..]
                    .find(seq_ready.as_bytes())
                    .is_some()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    output
}

pub struct ExifTool {
    process: Mutex<Child>,
}

pub struct ExifToolOutput {
    pub status: u8,
    pub output: Vec<u8>,
    pub error: Vec<u8>,
}

impl ExifTool {
    pub fn new() -> Self {
        let process =
            std::process::Command::new(std::env::var("EXIFTOOL").unwrap_or("exiftool".to_string()))
                .args(["-stay_open", "True", "-@", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
        ExifTool {
            process: Mutex::new(process),
        }
    }

    pub async fn execute(&self, params: Vec<String>) -> ExifToolOutput {
        let signal_num = 193280; // TODO: random #

        // # constant special sequences when running -stay_open mode
        let seq_execute = format!("-execute{}", signal_num); // the default string is b"-execute\n"
        let seq_ready = format!("{{ready{}}}", signal_num); // the default string is b"{ready}"
        let seq_err_post = format!("post{}", signal_num); //default there isn't any string

        let seq_err_status = "${status}"; // a special sequence, ${status} returns EXIT STATUS as per exiftool documentation - only supported on exiftool v12.10+

        let mut cmd_params: Vec<_> = params.into_iter().map(|s| s.into_bytes()).collect();
        cmd_params.push(b"-echo4".to_vec());
        cmd_params.push(
            format!("{SEQ_ERR_STATUS_DELIM}{seq_err_status}{SEQ_ERR_STATUS_DELIM}{seq_err_post}")
                .into_bytes(),
        );
        cmd_params.push(seq_execute.into_bytes());
        let message = {
            let mut s = Vec::new();
            for param in cmd_params {
                s.extend_from_slice(&param);
                s.extend_from_slice(b"\n");
            }
            s
        };

        let (mut raw_stdout, mut raw_stderr) = {
            let mut process = self.process.lock().await;
            let stdin = process.stdin.as_mut().unwrap();
            stdin.write_all(&message).unwrap();
            stdin.flush().unwrap();

            let stdout = process.stdout.as_mut().unwrap();
            let raw_stdout = read_fd_ends_with(stdout, seq_ready.as_str(), 4096).await;

            let stderr = process.stderr.as_mut().unwrap();
            let raw_stderr = read_fd_ends_with(stderr, seq_err_post.as_str(), 4096).await;

            (raw_stdout, raw_stderr)
        };

        trim_end(&mut raw_stdout);
        trim_end(&mut raw_stderr);
        raw_stdout.truncate(raw_stdout.len() - seq_ready.len());
        raw_stderr.truncate(raw_stderr.len() - seq_err_post.len());

        let err_status_delim = SEQ_ERR_STATUS_DELIM;
        if !raw_stderr.ends_with(err_status_delim.as_bytes()) {
            panic!("exiftool stderr did not end with {err_status_delim}");
        }

        let status_code = {
            let delim_len = err_status_delim.len();
            let next_delim = raw_stderr[..raw_stderr.len() - delim_len]
                .rfind(err_status_delim)
                .unwrap();
            let status_code = &raw_stderr[next_delim + delim_len..raw_stderr.len() - delim_len];
            let status_code = u8::from_str(std::str::from_utf8(status_code).unwrap()).unwrap();
            raw_stderr.truncate(next_delim);
            status_code
        };

        ExifToolOutput {
            status: status_code,
            output: raw_stdout,
            error: raw_stderr,
        }
    }

    pub async fn execute_json(&self, mut params: Vec<String>) -> Value {
        params.insert(0, "-j".to_string());
        serde_json::from_slice(&self.execute(params).await.output).unwrap()
    }

    pub async fn get_tags(
        &self,
        mut params: Vec<String>,
        tags: Vec<String>,
        files: Vec<String>,
    ) -> Value {
        params.extend(tags.into_iter().map(|mut t| {
            t.insert(0, '-');
            t
        }));
        params.extend(files.into_iter());
        self.execute_json(params).await
    }

    pub async fn preview(&self, path: &str) -> Vec<u8> {
        self
            .execute(vec![
                "-b".to_string(),
                "-PreviewImage".to_string(),
                path.to_string(),
            ])
            .await
            .output

    }
}
