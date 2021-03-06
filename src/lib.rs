use indexmap::set::Iter;
use indexmap::IndexSet;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::Rng;
use std::char::ParseCharError;
use std::fmt;
use std::str::FromStr;

/// Collection of unique chars
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Pool(IndexSet<char>);

impl FromStr for Pool {
    type Err = ParseCharError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Pool(s.chars().collect::<IndexSet<char>>()))
    }
}

impl fmt::Display for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.iter().collect::<String>())
    }
}

impl Pool {
    /// Create new empty pool
    pub fn new() -> Self {
        Pool(IndexSet::new())
    }

    /// Return number of chars in the pool
    ///
    /// # Examples
    /// ```
    /// # use upwd_lib::Pool;
    /// let pool: Pool = "0123456789".parse().unwrap();
    ///
    /// assert_eq!(pool.len(), 10)
    /// ```
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Extracts all chars from string and adds them to the pool
    pub fn extend_from_string(&mut self, s: &str) -> &mut Self {
        self.0.extend(s.chars().collect::<IndexSet<char>>());

        self
    }

    /// Returns true if pool contains no elements
    ///
    /// # Examples
    /// ```
    /// # use upwd_lib::Pool;
    /// let pool = Pool::new();
    ///
    /// assert!(pool.is_empty())
    /// ```
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get char by index
    pub(crate) fn get(&self, index: usize) -> Option<&char> {
        self.0.get_index(index)
    }

    /// Check if `element` exists in the pool
    ///
    /// # Examples
    /// ```
    /// # use upwd_lib::Pool;
    /// let pool: Pool = "ABCDEFG".parse().unwrap();
    ///
    /// assert!(pool.contains('D'))
    /// ```
    pub fn contains(&self, ch: char) -> bool {
        self.0.contains(&ch)
    }

    /// Returns true if pool contains each char from the string `elements`
    ///
    /// # Examples
    /// ```
    /// # use upwd_lib::Pool;
    /// let pool: Pool = "ABCDEFG".parse().unwrap();
    ///
    /// assert!(pool.contains_all("DAG"))
    /// ```
    pub fn contains_all(&self, elements: &str) -> bool {
        self.0
            .is_superset(&elements.chars().collect::<IndexSet<char>>())
    }

    /// Insert char to pool.
    /// If an equivalent char already exists in the pool, then the pool is not changed.
    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, ch: char) {
        self.0.insert(ch);
    }

    /// Returns iterator
    pub fn iter(&self) -> Iter<'_, char> {
        self.0.iter()
    }

    pub fn swap_remove(&mut self, ch: &char) -> bool {
        self.0.swap_remove(ch)
    }

    pub fn shift_remove(&mut self, ch: &char) -> bool {
        self.0.shift_remove(ch)
    }

    pub fn remove_all(&mut self, elements: &str) {
        elements.chars().for_each(|ch| {
            self.swap_remove(&ch);
        });
    }
}

/// Generate random password.
///
/// # Examples
/// ```
/// # use upwd_lib::{Pool, generate_password};
/// let pool = "0123456789".parse().unwrap();
/// let password = generate_password(&pool, 15);
///
/// assert_eq!(password.len(), 15);
/// ```
///
/// # Panics
/// Panics if `pool` is empty.
pub fn generate_password(pool: &Pool, length: usize) -> String {
    assert!(!pool.is_empty(), "Pool contains no elements!");

    let mut rng = rand::thread_rng();

    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0, pool.len());
            *pool.get(idx).unwrap()
        })
        .collect()
}

/// Calculates entropy.
///
/// # Examples
/// ```
/// # use upwd_lib::calculate_entropy;
///
/// assert_eq!(calculate_entropy(12, 64), 72.0);
/// ```
///
/// # Panics
/// Panics if `pool_size` is zero
pub fn calculate_entropy(length: usize, pool_size: usize) -> f64 {
    assert!(pool_size > 0, "Pool size must be greater than zero!");

    BigUint::from(pool_size)
        .pow(length as u32)
        .to_f64()
        .unwrap_or(f64::MAX)
        .log2()
}

/// Calculates the minimum password length required to obtain a given entropy.
///
/// # Examples
/// ```
/// # use upwd_lib::calculate_length;
///
/// assert_eq!(calculate_length(128.0, 64.0).ceil(), 22.0);
/// ```
pub fn calculate_length(entropy: f64, pool_size: f64) -> f64 {
    entropy / pool_size.log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_remove_all() {
        let mut pool: Pool = "abcde".parse().unwrap();
        pool.remove_all("ace");

        assert_eq!(pool, "bd".parse::<Pool>().unwrap());
    }

    #[test]
    fn pool_swap_remove() {
        let mut pool: Pool = "abcdefz".parse().unwrap();

        assert!(pool.swap_remove(&'b'));
        assert_eq!(pool.get(1), Some(&'z'));
        assert_eq!(pool.get(6), None);
    }

    #[test]
    fn pool_shift_remove() {
        let mut pool: Pool = "abcdefz".parse().unwrap();

        assert!(pool.shift_remove(&'b'));
        assert_eq!(pool.get(1), Some(&'c'));
        assert_eq!(pool.get(6), None);
    }

    #[test]
    fn pool_iter() {
        let pool: Pool = "abcdefz".parse().unwrap();
        let mut iter = pool.iter();

        assert_eq!(iter.next(), Some(&'a'));
        assert_eq!(iter.next(), Some(&'b'));
        assert_eq!(iter.last(), Some(&'z'));
    }

    #[test]
    fn pool_display() {
        let pool: Pool = "0123456789".parse().unwrap();

        assert_eq!(pool.to_string(), "0123456789".to_owned());
    }

    #[test]
    fn pool_contains_all() {
        let pool: Pool = "0123456789".parse().unwrap();

        assert!(pool.contains_all("2357"));
    }

    #[test]
    fn pool_contains_all_assert_false() {
        let pool: Pool = "0123456789".parse().unwrap();

        assert!(!pool.contains_all("0123F"));
    }

    #[test]
    fn pool_contains() {
        let pool: Pool = "0123456789".parse().unwrap();

        assert!(pool.contains('5'));
    }

    #[test]
    fn pool_contains_assert_false() {
        let pool: Pool = "0123456789".parse().unwrap();

        assert!(!pool.contains('A'));
    }

    #[test]
    fn pool_get() {
        let pool: Pool = "ABCD".parse().unwrap();

        assert_eq!(pool.get(0), Some(&'A'))
    }

    #[test]
    fn pool_is_empty() {
        let pool = Pool::new();

        assert!(pool.is_empty());
    }

    #[test]
    fn pool_is_empty_assert_false() {
        let pool = Pool::from_str("0123456789").unwrap();

        assert!(!pool.is_empty());
    }

    #[test]
    fn pool_len() {
        let pool: Pool = "0123456789".parse().unwrap();

        assert_eq!(pool.len(), 10)
    }

    #[test]
    fn pool_insert() {
        let mut pool = "ABC".parse::<Pool>().unwrap();
        pool.insert('D');

        assert_eq!(pool, "ABCD".parse::<Pool>().unwrap())
    }

    #[test]
    fn pool_extend_from_string() {
        let mut pool = "ABC".parse::<Pool>().unwrap();
        let mut other_pool = pool.clone();

        other_pool.insert('D');
        pool.extend_from_string("D");

        assert_eq!(other_pool, pool)
    }

    #[test]
    fn pool_from_string() {
        let indexset: IndexSet<_> = "0123456789".chars().collect();

        assert_eq!(Pool(indexset), "0123456789".to_owned().parse().unwrap())
    }

    #[test]
    fn pool_from_str() {
        let indexset: IndexSet<_> = "0123456789".chars().collect();

        assert_eq!(Pool(indexset), "0123456789".parse().unwrap())
    }

    #[test]
    fn generate_password_assert_len() {
        let pool = "0123456789".chars().collect::<IndexSet<char>>();
        let password = generate_password(&Pool(pool), 15);

        assert_eq!(password.len(), 15);
    }

    #[test]
    #[should_panic(expected = "Pool contains no elements!")]
    fn generate_password_passed_empty_pool() {
        let pool = "".chars().collect::<IndexSet<char>>();

        generate_password(&Pool(pool), 15);
    }

    #[test]
    fn calculate_entropy_assert_true() {
        let entropy = calculate_entropy(12, 64);

        assert_eq!(entropy, 72.0);
    }

    #[test]
    fn calculate_entropy_passed_length_is_0() {
        let entropy = calculate_entropy(0, 64);

        assert_eq!(entropy, 0.0)
    }

    #[test]
    #[should_panic(expected = "Pool size must be greater than zero!")]
    fn calculate_entropy_passed_pool_size_is_0() {
        calculate_entropy(12, 0);
    }

    #[test]
    fn calculate_entropy_passed_pool_size_is_1() {
        let entropy = calculate_entropy(12, 1);

        assert_eq!(entropy, 0.0)
    }

    #[test]
    fn calculate_length_assert_true() {
        let length = calculate_length(128.0, 64.0);

        assert_eq!(length.ceil(), 22.0);
    }

    #[test]
    fn calculate_length_entropy_is_0() {
        let length = calculate_length(0.0, 64.0);

        assert_eq!(length, 0.0);
    }

    #[test]
    fn calculate_length_pool_size_is_0() {
        let length = calculate_length(128.0, 0.0);

        assert_eq!(length, 0.0);
    }
}
