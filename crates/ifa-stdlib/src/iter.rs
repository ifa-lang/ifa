//! Higher-order functional iterator algorithms and zero-cost closure adapters.
//!
//! Provides idiomatic collection transformations (`map`, `filter`, `fold`, `for_each`,
//! `find`, `any`, `all`, `reduce`, `partition`) designed for predictable, allocation-conscious
//! execution on slices and collections.

/// Maps each element of a slice using a transformation closure, returning a new `Vec<U>`.
pub fn map<T, U, F>(items: &[T], mut transform: F) -> Vec<U>
where
    F: FnMut(&T) -> U,
{
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        result.push(transform(item));
    }
    result
}

/// Filters elements from a slice based on a predicate closure, returning matching elements.
pub fn filter<T: Clone, F>(items: &[T], mut predicate: F) -> Vec<T>
where
    F: FnMut(&T) -> bool,
{
    let mut result = Vec::new();
    for item in items {
        if predicate(item) {
            result.push(item.clone());
        }
    }
    result
}

/// Accumulates values of a slice starting from an initial accumulator.
pub fn fold<T, A, F>(items: &[T], initial: A, mut accumulator: F) -> A
where
    F: FnMut(A, &T) -> A,
{
    let mut acc = initial;
    for item in items {
        acc = accumulator(acc, item);
    }
    acc
}

/// Executes a closure for each element in the slice.
pub fn for_each<T, F>(items: &[T], mut action: F)
where
    F: FnMut(&T),
{
    for item in items {
        action(item);
    }
}

/// Finds the first element in a slice matching the predicate, if any.
pub fn find<T: Clone, F>(items: &[T], mut predicate: F) -> Option<T>
where
    F: FnMut(&T) -> bool,
{
    for item in items {
        if predicate(item) {
            return Some(item.clone());
        }
    }
    None
}

/// Returns true if at least one element satisfies the predicate closure.
pub fn any<T, F>(items: &[T], mut predicate: F) -> bool
where
    F: FnMut(&T) -> bool,
{
    for item in items {
        if predicate(item) {
            return true;
        }
    }
    false
}

/// Returns true if all elements in the slice satisfy the predicate closure.
pub fn all<T, F>(items: &[T], mut predicate: F) -> bool
where
    F: FnMut(&T) -> bool,
{
    for item in items {
        if !predicate(item) {
            return false;
        }
    }
    true
}

/// Reduces a non-empty slice using an accumulator closure.
pub fn reduce<T: Clone, F>(items: &[T], mut reducer: F) -> Option<T>
where
    F: FnMut(T, &T) -> T,
{
    let mut iter = items.iter();
    let first = iter.next()?.clone();
    let mut acc = first;
    for item in iter {
        acc = reducer(acc, item);
    }
    Some(acc)
}

/// Partitions a slice into two collections: elements satisfying the predicate, and those that do not.
pub fn partition<T: Clone, F>(items: &[T], mut predicate: F) -> (Vec<T>, Vec<T>)
where
    F: FnMut(&T) -> bool,
{
    let mut matching = Vec::new();
    let mut non_matching = Vec::new();
    for item in items {
        if predicate(item) {
            matching.push(item.clone());
        } else {
            non_matching.push(item.clone());
        }
    }
    (matching, non_matching)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_and_filter() {
        let numbers = vec![1, 2, 3, 4, 5, 6];
        let factor = 10;
        let scaled = map(&numbers, |&x| x * factor);
        assert_eq!(scaled, vec![10, 20, 30, 40, 50, 60]);

        let evens = filter(&numbers, |&x| x % 2 == 0);
        assert_eq!(evens, vec![2, 4, 6]);
    }

    #[test]
    fn test_fold_and_reduce() {
        let values = vec![10, 20, 30, 40];
        let sum = fold(&values, 0, |acc, &x| acc + x);
        assert_eq!(sum, 100);

        let product = reduce(&values, |acc, &x| acc * x);
        assert_eq!(product, Some(240000));
    }

    #[test]
    fn test_predicates_and_partition() {
        let words = vec!["ifa", "rust", "compiler", "systems"];
        assert!(any(&words, |&w| w.len() > 7));
        assert!(!all(&words, |&w| w.len() > 5));

        let (long_words, short_words) = partition(&words, |&w| w.len() > 4);
        assert_eq!(long_words, vec!["compiler", "systems"]);
        assert_eq!(short_words, vec!["ifa", "rust"]);
    }
}
