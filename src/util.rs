use std::sync::RwLock;

pub trait RwLockExt<T> {
    /// An efficient combinator for conditonally applying a write action.
    ///
    /// Acquires a read lock and applies the predicate, if it succeeds
    /// acquire a write lock and run the predicate again (since the data
    /// may have changed since releasing the read lock) and if it still
    /// succeeds run the provided action.
    ///
    /// Returns Some(the value returned by action) if the action is run,
    /// None otherwise. If the action is not run, then the predicate must
    /// have been false at least once.
    fn if_then<P, A, R>(&self, predicate: P, action: A) -> Option<R>
    where P: Fn(&T) -> bool, A: FnOnce(&mut T) -> R;
}

impl<T> RwLockExt<T> for RwLock<T> {
    fn if_then<P, A, R>(&self, predicate: P, action: A) -> Option<R>
    where P: Fn(&T) -> bool, A: FnOnce(&mut T) -> R {
        if predicate(&self.read().unwrap()) {
            let mut writer = self.write().unwrap();
            if predicate(&writer) {
                return Some(action(&mut writer))
            }
        };

        None
    }
}

pub mod test {
    /// Generate a random block of data of the given size.
    pub fn gen_random_block(block_size: usize) -> Vec<u8> {
        vec![::rand::random::<u8>(); block_size]
    }

    /// Generate a single random object with a random versioned history.
    pub fn gen_random_object(block_size: usize, num_versions: usize) -> Vec<Vec<u8>> {
        vec![gen_random_block(block_size); num_versions]
    }
}

