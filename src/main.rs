use hex::FromHex;
use native_dialog::FileDialog;
use std::path::PathBuf;
use std::time::Instant;

use slint::{Model, SharedString};
use std::sync::{Arc, Mutex};
mod aes_ctr_optimized;
mod thread_pool;

slint::include_modules!();

pub struct State {
    pub ui: MainWindow,
    pub job_model: std::rc::Rc<slint::VecModel<Job>>,
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

fn main() {
    let state = init_ui();
    let main_window = state.ui.clone_strong();
    main_window.run().unwrap();
}

fn init_ui() -> State {
    let mut jobs: Vec<Job> = Vec::new();
    let path = PathBuf::new();
    let app = MainWindow::new().unwrap();
    let selected_path = Arc::new(Mutex::new(path));
    let selected_output_path = Arc::new(Mutex::new(PathBuf::new()));

    for i in 1..=app.get_number_of_thread() {
        jobs.push(Job {
            name: SharedString::from(format!("Thread {i}: ")),
            counter: 0,
        });
    }
    println!("Jobs: {jobs:#?}");
    let job_model = std::rc::Rc::new(slint::VecModel::<Job>::from(jobs));

    let app_pointer: slint::Weak<MainWindow> = app.as_weak();

    print_ui_information(&app_pointer.clone());

    let weak_ui = app.as_weak();
    let selected_in_path_to_move = selected_path.clone();
    let selected_out_path_to_move = selected_output_path.clone();
    app.on_open_file_dialog(move |file_type: SharedString| {
        let cwd = std::env::current_dir().unwrap();
        let file_path = FileDialog::new()
            .set_location(&cwd)
            // .add_filter("PNG Image", &["png"])
            // .add_filter("JPEG Image", &["jpg", "jpeg"])
            .show_open_single_file()
            .unwrap();

        if let Some(path) = file_path {
            let basename = path.file_name().unwrap().to_str().unwrap().to_string();
            match file_type.as_str() {
                "input-file" => {
                    weak_ui.unwrap().set_input_filename(basename.into());
                    let mut full_path = selected_in_path_to_move.lock().unwrap();
                    *full_path = path.clone();
                }
                _ => {
                    weak_ui.unwrap().set_output_filename(basename.into());
                    let mut full_path = selected_out_path_to_move.lock().unwrap();
                    *full_path = path.clone();
                }
            }
        }
    });

    app.on_update_thread_number({
        let weak_ui = app.as_weak();
        let jobs = job_model.clone();

        move || {
            let app = weak_ui.unwrap();
            if app.get_number_of_thread() > jobs.row_count() as i32 {
                // Number of threads increased
                println!(
                    "Increase the number of thread: {}",
                    app.get_number_of_thread()
                );
                jobs.push(Job {
                    name: SharedString::from(format!("Thread {}: ", app.get_number_of_thread())),
                    counter: 0,
                });
            } else {
                println!(
                    "Decrease the number of thread: {}",
                    app.get_number_of_thread()
                );

                jobs.remove(jobs.row_count() - 1); // Number of thread decreased
            }
            app.set_jobs(jobs.clone().into());
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
        let selected_path = selected_path.clone();
        let selected_output_path = selected_output_path.clone();

        move || {
            let app = weak_ui.unwrap();
            let mut key_size: u16 = 0;
            let mut error_occur: bool = false;
            let mut key_bytes: Vec<u8> = Vec::new();
            let mut iv_bytes: Vec<u8> = Vec::new();
            let number_thread = app.get_number_of_thread() as u64;
            let chunk_size = app.get_quantity_pro_thread() as usize;

            match app.get_key().len() * 4 {
                128 | 256 => match Vec::from_hex(app.get_key()) {
                    Ok(bytes) => {
                        key_bytes = bytes;
                        key_size = app.get_key().len() as u16 * 4;
                    }
                    Err(e) => {
                        eprintln!("!!! ERROR: Key hex string parsing failed: {}", e);
                        error_occur = true;
                    }
                },
                _ => {
                    eprintln!(
                        concat!(
                            "!!! ERROR: Key hex string neither matches 128-bit nor 256-bit size!\n",
                            "!!!        (is {} characters long, but should be 32 or 64)"
                        ),
                        app.get_key().len()
                    );
                    error_occur = true;
                }
            }

            match app.get_nonce().len() * 4 {
                128 | 256 => match Vec::from_hex(app.get_nonce()) {
                    Ok(bytes) => iv_bytes = bytes,
                    Err(e) => {
                        eprintln!("!!! ERROR: Key hex string parsing failed: {}", e);
                        error_occur = true;
                    }
                },
                _ => {
                    eprintln!(
                        concat!(
                            "!!! ERROR: IV hex string neither matches 128-bit nor 256-bit size!\n",
                            "!!!        (is {} characters long, but should be 32 or 64)"
                        ),
                        app.get_nonce().len()
                    );
                    error_occur = true;
                }
            }

            if error_occur {
                eprintln!("You are dumass");
                return;
            }
            let selected_path = selected_path.clone();
            let selected_output_path = selected_output_path.clone();
            let handle = std::thread::spawn(move || {
                let input_file_path = selected_path.lock().unwrap();
                let output_file_path = selected_output_path.lock().unwrap();
                let now = Instant::now();

                aes_ctr_optimized::handle_aes_ctr_command(
                    "Encrypt".to_owned(),
                    key_size,
                    key_bytes,
                    iv_bytes,
                    input_file_path.clone(),
                    output_file_path.clone(),
                    number_thread,
                    chunk_size,
                );
                println!(
                    "\n### Finished! It took {:.10} seconds!",
                    now.elapsed().as_secs_f32()
                );
            });
           let _ = handle.join();
        }
    });

    app.set_jobs(job_model.clone().into());
    State { ui: app, job_model }
}
