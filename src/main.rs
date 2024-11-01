use hex::FromHex;
use native_dialog::FileDialog;
use slint::{Model, SharedString, VecModel};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
mod aes_ctr_optimized;
mod thread_pool;

slint::include_modules!();

pub struct State {
    pub ui: MainWindow,
    pub job_model: Rc<slint::VecModel<Job>>,
}

enum Color {
    Red,
    Green,
    Blue,
}
fn get_color(color: Color) -> slint::Brush {
    return match color {
        Color::Blue => slint::Brush::SolidColor(slint::Color::from_rgb_u8(0, 255, 0)),
        Color::Red => slint::Brush::SolidColor(slint::Color::from_rgb_u8(255, 0, 0)),
        Color::Green => slint::Brush::SolidColor(slint::Color::from_rgb_u8(0, 255, 0)),
    };
}

fn print_ui_information(app_pointer: &slint::Weak<MainWindow>) {
    let app = app_pointer.upgrade().unwrap();
    println!("Key for encryption: {}", app.get_key());
    println!("Nonce for encryption: {}", app.get_nonce());
    println!("Number of Thread: {}", app.get_number_of_thread());
    println!(
        "Number of MB for each Thread: {}",
        app.get_quantity_pro_thread()
    );
}

// Get file size in MB
fn get_file_size_in_mb(path: &PathBuf) -> Result<f32, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    let size_in_bytes = metadata.len() as f32 / 1_048_576.0;
    Ok(size_in_bytes.ceil())
}

fn main() {
    let state = init_ui();
    let main_window = state.ui.clone_strong();
    main_window.run().unwrap();
}

fn init_ui() -> State {
    let path = PathBuf::new();
    let mut jobs: Vec<Job> = Vec::new();
    let app = MainWindow::new().unwrap();
    let counter = Arc::new(Mutex::new(0f32));
    let filesize = Arc::new(Mutex::new(0f32));
    let stop_encryption = Arc::new(Mutex::new(false));
    let selected_in_path = Arc::new(Mutex::new(path));
    let selected_output_path = Arc::new(Mutex::new(PathBuf::new()));

    for i in 1..=app.get_number_of_thread() {
        jobs.push(Job {
            name: slint::format!("Thread {i}: "),
            counter: 0,
        });
    }
    let job_model: Rc<VecModel<Job>> = Rc::new(VecModel::<Job>::from(jobs.clone()));
    let app_pointer: slint::Weak<MainWindow> = app.as_weak();

    print_ui_information(&app_pointer.clone());

    app.on_open_file_dialog({
        let weak_ui = app.as_weak();
        let counter_thread = counter.clone();
        let filesize_thread = filesize.clone();
        let selected_in_path_thread = selected_in_path.clone();
        let selected_out_path_thread = selected_output_path.clone();

        move |file_type: SharedString| {
            let cwd = std::env::current_dir().unwrap();
            let file_path = FileDialog::new().set_location(&cwd).show_open_single_file();

            if let Ok(Some(path)) = file_path {
                let basename = path.file_name().unwrap().to_str().unwrap().to_string();
                match file_type.as_str() {
                    "input-file" => {
                        weak_ui.unwrap().set_input_filename(basename.into());
                        let mut full_path = selected_in_path_thread.lock().unwrap();
                        *full_path = path.clone();
                        let mut c = counter_thread.lock().unwrap();
                        *c = 0.0;
                        let mut size = filesize_thread.lock().unwrap();
                        *size = get_file_size_in_mb(&path).unwrap();
                        weak_ui.unwrap().set_filesize(*size as i32);
                    }
                    _ => {
                        weak_ui.unwrap().set_output_filename(basename.into());
                        let mut full_path = selected_out_path_thread.lock().unwrap();
                        *full_path = path.clone();
                    }
                }
            }
        }
    });

    app.on_update_thread_number({
        let weak_ui = app.as_weak();
        let jobs_thread = job_model.clone();

        move || {
            let app = weak_ui.unwrap();
            let number_of_thread = app.get_number_of_thread();

            println!(
                "Change the number of thread from {} to {number_of_thread}",
                jobs_thread.row_count()
            );
            let diff: i32 = number_of_thread - jobs_thread.row_count() as i32;
            for _ in 0..diff.abs() {
                if diff > 0 {
                    // Number of threads increased
                    jobs_thread.push(Job {
                        name: slint::format!("Thread {}: ", jobs_thread.row_count() + 1),
                        counter: 0,
                    });
                } else {
                    jobs_thread.remove(jobs_thread.row_count() - 1); // Number of thread decreased
                }
            }

            app.set_jobs(jobs_thread.clone().into());
        }
    });

    app.on_close_requested({
        let weak_ui = app.as_weak();
        move || {
            weak_ui.unwrap().hide().expect("Problem closing the UI");
        }
    });

    app.on_run_encryption({
        let weak_ui = app.as_weak();
        let counter_thread = counter.clone();
        let stop_encryption_thread = stop_encryption.clone();
        let selected_in_path_thread = selected_in_path.clone();
        let selected_output_path_thread = selected_output_path.clone();

        move || {
            let key_size: u16;
            let iv_bytes: Vec<u8>;
            let key_bytes: Vec<u8>;
            let app = weak_ui.clone().unwrap();
            let stop_encryption_thread = stop_encryption_thread.clone();
            let mut stop_encryption_value = stop_encryption_thread.lock().unwrap();

            if app.get_is_running() {
                println!("Computation already running.");
                return;
            }

            // Retrieve encryption parameters
            match app.get_key().len() * 4 {
                128 | 256 => match Vec::from_hex(app.get_key()) {
                    Ok(bytes) => {
                        key_bytes = bytes;
                        key_size = app.get_key().len() as u16 * 4;
                    }
                    Err(e) => {
                        app.set_status(slint::format!(
                            "!!! ERROR: Key hex string parsing failed: {e}",
                        ));
                        app.set_status_color(get_color(Color::Red));
                        return;
                    }
                },
                _ => {
                    app.set_status(SharedString::from("!!! ERROR: Invalid key length!"));
                    app.set_status_color(get_color(Color::Red));
                    return;
                }
            }

            match app.get_nonce().len() * 4 {
                128 | 256 => match Vec::from_hex(app.get_nonce()) {
                    Ok(bytes) => iv_bytes = bytes,
                    Err(e) => {
                        app.set_status(slint::format!(
                            "!!! ERROR: Nonce hex string parsing failed: {e}",
                        ));
                        app.set_status_color(get_color(Color::Red));
                        return;
                    }
                },
                _ => {
                    app.set_status("!!! ERROR: Invalid nonce length!".into());
                    app.set_status_color(get_color(Color::Red));
                    return;
                }
            }

            let number_thread = app.get_number_of_thread() as u64;
            let chunk_size = app.get_quantity_pro_thread() as usize;
            let (sender_ui, receiver_ui) = channel::<(usize, usize)>();

            // Thread to handle encryption
            let input_path = selected_in_path_thread.lock().unwrap().clone();
            let output_path = selected_output_path_thread.lock().unwrap().clone();

            if input_path.as_os_str().is_empty() {
                app.set_status_color(get_color(Color::Red));
                app.set_status("Please choose a file to encrypt".into());
                return;
            }
            if output_path.as_os_str().is_empty() {
                app.set_status_color(get_color(Color::Red));
                app.set_status("Please choose the output file".into());

                return;
            }

            app.set_is_running(true);
            app.set_progress_value(1f32);
            *stop_encryption_value = false;
            println!("on_run_encryption -> ",);
            app.set_status_color(get_color(Color::Green));
            app.set_status("Encryption Running ...".into());

            std::thread::spawn({
                let weak_ui = weak_ui.clone();
                let sender_ui_thread = sender_ui.clone();
                let stop_encryption_thread = stop_encryption_thread.clone();

                move || {
                    aes_ctr_optimized::handle_aes_ctr_command(
                        "Encrypt".to_string(),
                        key_size,
                        key_bytes,
                        iv_bytes,
                        input_path,
                        output_path,
                        number_thread,
                        chunk_size,
                        sender_ui_thread.clone(),
                        stop_encryption_thread.clone(),
                    );

                    slint::invoke_from_event_loop(move || {
                        if let Some(app) = weak_ui.upgrade() {
                            app.set_status_color(get_color(Color::Green));
                            if *stop_encryption_thread.lock().unwrap() {
                                app.set_status("Encryption Stopped!".into());
                            } else {
                                app.set_status("Encryption completed!".into());
                            }
                        }
                    })
                    .unwrap();
                }
            });

            // Thread to handle progress updates
            std::thread::spawn({
                let weak_ui = weak_ui.clone();
                let counter = counter_thread.clone();
                let filesize_thread = filesize.clone();

                move || loop {
                    if let Ok((id, nr_job)) = receiver_ui.try_recv() {
                        let weak_ui = weak_ui.clone();
                        let counter_thread = counter.clone();
                        let filesize_thread = filesize_thread.clone();

                        if nr_job == 0 {
                            continue;
                        }

                        slint::invoke_from_event_loop(move || {
                            if let Some(app) = weak_ui.upgrade() {
                                let job_data = app.get_jobs();
                                let mut job = job_data.row_data(id).unwrap();
                                job.counter = nr_job as i32;
                                let mut value = counter_thread.lock().unwrap();
                                *value += 1.0;
                                app.set_progress_value(
                                    1f32 - *value / *filesize_thread.lock().unwrap(),
                                );
                                job_data.set_row_data(id, job);
                                app.set_jobs(job_data);
                            }
                        })
                        .unwrap();
                    }
                }
            });
        }
    });

    app.on_stop_encryption({
        let weak_ui = app.as_weak();
        let stop_encryption_thread = stop_encryption.clone();

        move || {
            let mut stop_encryption_value = stop_encryption_thread.lock().unwrap();
            let app =weak_ui.upgrade().unwrap();
            app.set_is_running(false);
            app.set_status("Stopping encryption ... ".into());
            app.set_status_color(get_color(Color::Red));

            *stop_encryption_value = true;
        }
    });

    app.set_jobs(job_model.clone().into());

    State { ui: app, job_model }
}
