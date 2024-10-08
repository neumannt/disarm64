TEST(0x91000020, ADDxi(DA_GP(0), DA_GP(1), 0x0));
TEST(0x91000420, ADDxi(DA_GP(0), DA_GP(1), 0x1));
TEST(0x913ffc20, ADDxi(DA_GP(0), DA_GP(1), 0xfff));
TEST(0x91400420, ADDxi(DA_GP(0), DA_GP(1), 0x1000));
TEST(0x91400820, ADDxi(DA_GP(0), DA_GP(1), 0x2000));
TEST(0x917ffc20, ADDxi(DA_GP(0), DA_GP(1), 0xfff000));
TEST(0x91000020, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x0));
TEST(0xd1000420, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x1));
TEST(0xd13ffc20, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0xfff));
TEST(0xd1400420, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x1000));
TEST(0xd1400820, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x2000));
TEST(0xd17ffc20, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0xfff000));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), 0x1800));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x1800));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), 0x1001));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x1001));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), 0xffff));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0xffff));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), 0x1000000));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x1000000));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), 0x1000000000000));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), -(uint64_t)0x1000000000000));
TEST(0, ADDxi(DA_GP(0), DA_GP(1), 0x7fffffffffffffff));
TEST(0x91000400, ADDxi(DA_GP(0), DA_GP(0), 0x1));
TEST(0xd1000400, SUBxi(DA_GP(0), DA_GP(0), 0x1));
TEST(0xd1000400, ADDxi(DA_GP(0), DA_GP(0), -0x1));
TEST(0x91000400, SUBxi(DA_GP(0), DA_GP(0), -0x1));
TEST(0x913ffc00, ADDxi(DA_GP(0), DA_GP(0), 0xfff));
TEST(0xd13ffc00, SUBxi(DA_GP(0), DA_GP(0), 0xfff));
TEST(0xd13ffc00, ADDxi(DA_GP(0), DA_GP(0), -0xfff));
TEST(0x913ffc00, SUBxi(DA_GP(0), DA_GP(0), -0xfff));
TEST(0x91400400, ADDxi(DA_GP(0), DA_GP(0), 0x1000));
TEST(0xd1400400, SUBxi(DA_GP(0), DA_GP(0), 0x1000));
TEST(0xd1400400, ADDxi(DA_GP(0), DA_GP(0), -0x1000));
TEST(0x91400400, SUBxi(DA_GP(0), DA_GP(0), -0x1000));
TEST(0x917ffc00, ADDxi(DA_GP(0), DA_GP(0), 0xfff000));
TEST(0xd17ffc00, SUBxi(DA_GP(0), DA_GP(0), 0xfff000));
TEST(0xd17ffc00, ADDxi(DA_GP(0), DA_GP(0), -0xfff000));
TEST(0x917ffc00, SUBxi(DA_GP(0), DA_GP(0), -0xfff000));
TEST(0, ADDxi(DA_GP(0), DA_GP(0), 0xfff800));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0xfff800));
TEST(0, ADDxi(DA_GP(0), DA_GP(0), -0xfff800));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0xfff800));
TEST(0, ADDxi(DA_GP(0), DA_GP(0), 0x1800));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x1800));
TEST(0, ADDxi(DA_GP(0), DA_GP(0), -0x1800));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x1800));
TEST(0, ADDxi(DA_GP(0), DA_GP(0), 0x1000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x1000000));
TEST(0, ADDxi(DA_GP(0), DA_GP(0), -0x1000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x10000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x10000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x100000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x100000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x1000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x1000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x10000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x10000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x100000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x100000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x1000000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x1000000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), -0x10000000000000));
TEST(0, SUBxi(DA_GP(0), DA_GP(0), 0x10000000000000));
