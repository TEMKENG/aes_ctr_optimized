use std::sync::{
    Arc, Mutex,
    mpsc::{channel, Receiver, Sender},
};
use std::thread;

pub enum Message {
    NewJob(Job),
    Terminate,
}

pub type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct Worker {
    id: usize,
    counter: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    pub fn new(
        id: usize,
        receiver: Arc<Mutex<Receiver<Message>>>,
        sender_ui: Sender<(usize, usize)>,
        stop_encryption: Arc<Mutex<bool>>,
    ) -> Worker {
        let mut this = Worker {
            id,
            counter: 0,
            thread: None,
        };

        let worker_thread = Arc::new(Mutex::new(Worker {
            id,
            counter: 0,
            thread: None,
        }));

        let thread = thread::spawn(move || loop {
            let message: Message;
            {
                let receiver = receiver.lock().unwrap();
                message = receiver.recv().unwrap();
            }

            match message {
                Message::NewJob(job) => {
                    if *stop_encryption.lock().unwrap() == false {
                        job();
                        let mut worker_data = worker_thread.lock().unwrap();
                        worker_data.counter += 1;
                        sender_ui.send((id, worker_data.counter)).unwrap();
                    }
                }
                Message::Terminate => {
                    sender_ui.send((id, 0)).unwrap();
                    break;
                }
            }
        });
        this.thread = Some(thread);
        this
    }
}

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Sender<Message>,
}

impl ThreadPool {
    pub fn new(
        size: usize,
        sender_from_ui: Sender<(usize, usize)>,
        stop_encryption: Arc<Mutex<bool>>,
    ) -> ThreadPool {
        assert!(size > 0);

        let mut workers = Vec::with_capacity(size);
        let (sender, receiver) = channel::<Message>();
        let receiver = Arc::new(Mutex::new(receiver));

        for id in 0..size {
            workers.push(Worker::new(
                id,
                receiver.clone(),
                sender_from_ui.clone(),
                stop_encryption.clone(),
            ));
        }

        ThreadPool { workers, sender }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender.send(Message::NewJob(job)).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        for _ in &self.workers {
            self.sender.send(Message::Terminate).unwrap();
        }

        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
                println!("ThreadPool| Shutting down worker {}", worker.id);
            }
        }
    }
}
