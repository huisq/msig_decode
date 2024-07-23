module 0xaa90e0d9d16b63ba4a289fb0dc8d1b454058b21c9b5c76864f825d5c1f32582e::table_map {
    struct Element<T0: copy + drop + store, T1: copy + drop + store> has copy, drop, store {
        key: T0,
        value: T1,
    }
    
    struct TableMap<T0: copy + drop + store, T1: copy + drop + store> has store, key {
        index: 0x1::table::Table<T0, u64>,
        data: 0x1::table_with_length::TableWithLength<u64, Element<T0, T1>>,
    }
    
    public fun add<T0: copy + drop + store, T1: copy + drop + store>(arg0: &mut TableMap<T0, T1>, arg1: T0, arg2: T1) {
        let (v0, _) = find<T0, T1>(arg0, &arg1);
        assert!(!v0, 0x1::error::invalid_argument(1));
        let v2 = 0x1::table_with_length::length<u64, Element<T0, T1>>(&arg0.data);
        0x1::table::add<T0, u64>(&mut arg0.index, arg1, v2);
        let v3 = Element<T0, T1>{
            key   : arg1, 
            value : arg2,
        };
        0x1::table_with_length::add<u64, Element<T0, T1>>(&mut arg0.data, v2, v3);
    }
    
    public fun borrow<T0: copy + drop + store, T1: copy + drop + store>(arg0: &TableMap<T0, T1>, arg1: &T0) : &T1 {
        let (v0, v1) = find<T0, T1>(arg0, arg1);
        assert!(v0, 0x1::error::invalid_argument(2));
        &0x1::table_with_length::borrow<u64, Element<T0, T1>>(&arg0.data, v1).value
    }
    
    public fun remove<T0: copy + drop + store, T1: copy + drop + store>(arg0: &mut TableMap<T0, T1>, arg1: &T0) : (T0, T1) {
        let (v0, v1) = find<T0, T1>(arg0, arg1);
        assert!(v0, 0x1::error::invalid_argument(2));
        swap<T0, T1>(arg0, v1, length<T0, T1>(arg0) - 1);
        let Element {
            key   : v2,
            value : v3,
        } = pop_back<T0, T1>(arg0);
        (v2, v3)
    }
    
    public fun borrow_mut<T0: copy + drop + store, T1: copy + drop + store>(arg0: &mut TableMap<T0, T1>, arg1: &T0) : &mut T1 {
        let (v0, v1) = find<T0, T1>(arg0, arg1);
        assert!(v0, 0x1::error::invalid_argument(2));
        &mut 0x1::table_with_length::borrow_mut<u64, Element<T0, T1>>(&mut arg0.data, v1).value
    }
    
    public fun length<T0: copy + drop + store, T1: copy + drop + store>(arg0: &TableMap<T0, T1>) : u64 {
        0x1::table_with_length::length<u64, Element<T0, T1>>(&arg0.data)
    }
    
    fun pop_back<T0: copy + drop + store, T1: copy + drop + store>(arg0: &mut TableMap<T0, T1>) : Element<T0, T1> {
        let v0 = 0x1::table_with_length::remove<u64, Element<T0, T1>>(&mut arg0.data, length<T0, T1>(arg0) - 1);
        0x1::table::remove<T0, u64>(&mut arg0.index, v0.key);
        v0
    }
    
    fun swap<T0: copy + drop + store, T1: copy + drop + store>(arg0: &mut TableMap<T0, T1>, arg1: u64, arg2: u64) {
        if (arg1 == arg2) {
            return
        };
        let v0 = *0x1::table_with_length::borrow<u64, Element<T0, T1>>(&arg0.data, arg1);
        let v1 = *0x1::table_with_length::borrow<u64, Element<T0, T1>>(&arg0.data, arg2);
        0x1::table_with_length::upsert<u64, Element<T0, T1>>(&mut arg0.data, arg1, v1);
        0x1::table_with_length::upsert<u64, Element<T0, T1>>(&mut arg0.data, arg2, v0);
        0x1::table::upsert<T0, u64>(&mut arg0.index, v0.key, *0x1::table::borrow<T0, u64>(&arg0.index, v1.key));
        0x1::table::upsert<T0, u64>(&mut arg0.index, v1.key, *0x1::table::borrow<T0, u64>(&arg0.index, v0.key));
    }
    
    public fun at<T0: copy + drop + store, T1: copy + drop + store>(arg0: &TableMap<T0, T1>, arg1: u64) : (&T0, &T1) {
        let v0 = 0x1::table_with_length::borrow<u64, Element<T0, T1>>(&arg0.data, arg1);
        (&v0.key, &v0.value)
    }
    
    public fun contains_key<T0: copy + drop + store, T1: copy + drop + store>(arg0: &TableMap<T0, T1>, arg1: &T0) : bool {
        0x1::table::contains<T0, u64>(&arg0.index, *arg1)
    }
    
    public fun create<T0: copy + drop + store, T1: copy + drop + store>() : TableMap<T0, T1> {
        TableMap<T0, T1>{
            index : 0x1::table::new<T0, u64>(), 
            data  : 0x1::table_with_length::new<u64, Element<T0, T1>>(),
        }
    }
    
    fun find<T0: copy + drop + store, T1: copy + drop + store>(arg0: &TableMap<T0, T1>, arg1: &T0) : (bool, u64) {
        if (0x1::table::contains<T0, u64>(&arg0.index, *arg1)) {
            (true, *0x1::table::borrow<T0, u64>(&arg0.index, *arg1))
        } else {
            (false, 18446744073709551615)
        }
    }
    
    public fun from_vectors<T0: copy + drop + store, T1: copy + drop + store>(arg0: &vector<T0>, arg1: &vector<T1>) : TableMap<T0, T1> {
        assert!(0x1::vector::length<T0>(arg0) == 0x1::vector::length<T1>(arg1), 3);
        let v0 = create<T0, T1>();
        let v1 = 0;
        while (v1 < 0x1::vector::length<T0>(arg0)) {
            add<T0, T1>(&mut v0, *0x1::vector::borrow<T0>(arg0, v1), *0x1::vector::borrow<T1>(arg1, v1));
            v1 = v1 + 1;
        };
        v0
    }
    
    // decompiled from Move bytecode v6
}

