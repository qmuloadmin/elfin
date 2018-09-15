use std::fs::File;
    #[test]
    fn it_works() {
        let mut headers = super::ElfHeaders::new();
        let mut file = File::open("/usr/bin/python").unwrap();
        let result = headers.from_file(&mut file);
        match result {
            Ok(x) => assert_eq!(x, ()),
            Err(x) => panic!(x)
        };
        let sections = headers.sections_from_file(&mut file).unwrap();
        println!("{}", headers);
        println!("\nSections:\n");
        for section in sections {
            println!("{}", section);
        }
    }