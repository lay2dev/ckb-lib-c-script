mod test_c_file {
    use ckb_lib_smt::get_libsmt_bin;

    #[test]
    fn test_get_c_bin() {
        println!("{:?}", get_libsmt_bin());
    }
}
