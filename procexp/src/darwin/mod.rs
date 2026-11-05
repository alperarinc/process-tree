pub mod libproc;
pub mod meta;
pub mod windows;

/// Run the calling thread at background QoS (efficiency cores, low I/O priority).
pub fn set_background_qos() {
    unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_BACKGROUND, 0) };
}
