use ark_ff::FftField;
use secret_sharing::pss::PackedSharingParams;

#[allow(unused)]
/// Pack a vector of secrets to many vectors of shares. Each output vector packs l secrets in the input vector.
/// Panic if the size of the input vector is not a multiple of l.
pub fn pack_vec<F: FftField>(
    secrets: &Vec<F>,
    pp: &PackedSharingParams<F>,
) -> Vec<Vec<F>> {
    debug_assert_eq!(secrets.len() % pp.l, 0, "Mismatch of size in pack_vec");

    // pack shares
    let shares = secrets
        .chunks(pp.l)
        .map(|x| pp.pack_from_public(x.to_vec()))
        .collect::<Vec<_>>();

    shares
}

/// Transpose a matrix
pub fn transpose<T: Clone>(matrix: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!matrix.is_empty());
    let cols = matrix[0].len();
    let rows = matrix.len();

    let mut result: Vec<Vec<T>> = vec![vec![matrix[0][0].clone(); rows]; cols];

    for (c, column) in result.iter_mut().enumerate().take(cols) {
        for (r, row) in matrix.iter().enumerate().take(rows) {
            column[r] = row[c].clone();
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpose() {
        let matrix = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        let expected = vec![vec![1, 4, 7], vec![2, 5, 8], vec![3, 6, 9]];

        assert_eq!(transpose(matrix), expected);
    }
}
