
// STR/LDR scaled immediate
TEST(0, STRbu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRbu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRbu(DA_V(1), DA_GP(0), -0x1));
TEST(0, LDRbu(DA_V(1), DA_GP(0), -0x1));
TEST(0x3d000001, STRbu(DA_V(1), DA_GP(0), 0));
TEST(0x3d400001, LDRbu(DA_V(1), DA_GP(0), 0));
TEST(0x3d000401, STRbu(DA_V(1), DA_GP(0), 0x1));
TEST(0x3d400401, LDRbu(DA_V(1), DA_GP(0), 0x1));
TEST(0x3d0007e1, STRbu(DA_V(1), DA_SP, 0x1));
TEST(0x3d4007e1, LDRbu(DA_V(1), DA_SP, 0x1));
TEST(0x3d000801, STRbu(DA_V(1), DA_GP(0), 0x2));
TEST(0x3d400801, LDRbu(DA_V(1), DA_GP(0), 0x2));
TEST(0x3d3ffc01, STRbu(DA_V(1), DA_GP(0), 0xfff));
TEST(0x3d7ffc01, LDRbu(DA_V(1), DA_GP(0), 0xfff));
TEST(0, STRbu(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRbu(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRbu(DA_V(1), DA_GP(0), 0x1ffe));
TEST(0, LDRbu(DA_V(1), DA_GP(0), 0x1ffe));
TEST(0, STRbu(DA_V(1), DA_GP(0), 0x1fff));
TEST(0, LDRbu(DA_V(1), DA_GP(0), 0x1fff));
TEST(0, STRbu(DA_V(1), DA_GP(0), 0x2000));
TEST(0, LDRbu(DA_V(1), DA_GP(0), 0x2000));
TEST(0, STRhu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRhu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRhu(DA_V(1), DA_GP(0), -0x1));
TEST(0, LDRhu(DA_V(1), DA_GP(0), -0x1));
TEST(0x7d000001, STRhu(DA_V(1), DA_GP(0), 0));
TEST(0x7d400001, LDRhu(DA_V(1), DA_GP(0), 0));
TEST(0, STRhu(DA_V(1), DA_GP(0), 0x1));
TEST(0, LDRhu(DA_V(1), DA_GP(0), 0x1));
TEST(0x7d000401, STRhu(DA_V(1), DA_GP(0), 0x2));
TEST(0x7d400401, LDRhu(DA_V(1), DA_GP(0), 0x2));
TEST(0x7d0007e1, STRhu(DA_V(1), DA_SP, 0x2));
TEST(0x7d4007e1, LDRhu(DA_V(1), DA_SP, 0x2));
TEST(0x7d1ffc01, STRhu(DA_V(1), DA_GP(0), 0xffe));
TEST(0x7d5ffc01, LDRhu(DA_V(1), DA_GP(0), 0xffe));
TEST(0, STRhu(DA_V(1), DA_GP(0), 0xfff));
TEST(0, LDRhu(DA_V(1), DA_GP(0), 0xfff));
TEST(0x7d200001, STRhu(DA_V(1), DA_GP(0), 0x1000));
TEST(0x7d600001, LDRhu(DA_V(1), DA_GP(0), 0x1000));
TEST(0x7d3ffc01, STRhu(DA_V(1), DA_GP(0), 0x1ffe));
TEST(0x7d7ffc01, LDRhu(DA_V(1), DA_GP(0), 0x1ffe));
TEST(0, STRhu(DA_V(1), DA_GP(0), 0x1fff));
TEST(0, LDRhu(DA_V(1), DA_GP(0), 0x1fff));
TEST(0, STRhu(DA_V(1), DA_GP(0), 0x2000));
TEST(0, LDRhu(DA_V(1), DA_GP(0), 0x2000));
TEST(0, STRhu(DA_V(1), DA_GP(0), 0x4000));
TEST(0, LDRhu(DA_V(1), DA_GP(0), 0x4000));
TEST(0, STRsu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRsu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRsu(DA_V(1), DA_GP(0), -0x1));
TEST(0, LDRsu(DA_V(1), DA_GP(0), -0x1));
TEST(0xbd000001, STRsu(DA_V(1), DA_GP(0), 0));
TEST(0xbd400001, LDRsu(DA_V(1), DA_GP(0), 0));
TEST(0, STRsu(DA_V(1), DA_GP(0), 0x1));
TEST(0, LDRsu(DA_V(1), DA_GP(0), 0x1));
TEST(0, STRsu(DA_V(1), DA_GP(0), 0x2));
TEST(0, LDRsu(DA_V(1), DA_GP(0), 0x2));
TEST(0xbd000401, STRsu(DA_V(1), DA_GP(0), 0x4));
TEST(0xbd400401, LDRsu(DA_V(1), DA_GP(0), 0x4));
TEST(0xbd0007e1, STRsu(DA_V(1), DA_SP, 0x4));
TEST(0xbd4007e1, LDRsu(DA_V(1), DA_SP, 0x4));
TEST(0xbd0ffc01, STRsu(DA_V(1), DA_GP(0), 0xffc));
TEST(0xbd4ffc01, LDRsu(DA_V(1), DA_GP(0), 0xffc));
TEST(0, STRsu(DA_V(1), DA_GP(0), 0xfff));
TEST(0, LDRsu(DA_V(1), DA_GP(0), 0xfff));
TEST(0xbd300001, STRsu(DA_V(1), DA_GP(0), 0x3000));
TEST(0xbd700001, LDRsu(DA_V(1), DA_GP(0), 0x3000));
TEST(0xbd3ffc01, STRsu(DA_V(1), DA_GP(0), 0x3ffc));
TEST(0xbd7ffc01, LDRsu(DA_V(1), DA_GP(0), 0x3ffc));
TEST(0, STRsu(DA_V(1), DA_GP(0), 0x3fff));
TEST(0, LDRsu(DA_V(1), DA_GP(0), 0x3fff));
TEST(0, STRsu(DA_V(1), DA_GP(0), 0x4000));
TEST(0, LDRsu(DA_V(1), DA_GP(0), 0x4000));
TEST(0, STRsu(DA_V(1), DA_GP(0), 0x8000));
TEST(0, LDRsu(DA_V(1), DA_GP(0), 0x8000));
TEST(0, STRdu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRdu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRdu(DA_V(1), DA_GP(0), -0x1));
TEST(0, LDRdu(DA_V(1), DA_GP(0), -0x1));
TEST(0xfd000001, STRdu(DA_V(1), DA_GP(0), 0));
TEST(0xfd400001, LDRdu(DA_V(1), DA_GP(0), 0));
TEST(0, STRdu(DA_V(1), DA_GP(0), 0x1));
TEST(0, LDRdu(DA_V(1), DA_GP(0), 0x1));
TEST(0, STRdu(DA_V(1), DA_GP(0), 0x2));
TEST(0, LDRdu(DA_V(1), DA_GP(0), 0x2));
TEST(0, STRdu(DA_V(1), DA_GP(0), 0x4));
TEST(0, LDRdu(DA_V(1), DA_GP(0), 0x4));
TEST(0xfd000401, STRdu(DA_V(1), DA_GP(0), 0x8));
TEST(0xfd400401, LDRdu(DA_V(1), DA_GP(0), 0x8));
TEST(0xfd0007e1, STRdu(DA_V(1), DA_SP, 0x8));
TEST(0xfd4007e1, LDRdu(DA_V(1), DA_SP, 0x8));
TEST(0xfd07fc01, STRdu(DA_V(1), DA_GP(0), 0xff8));
TEST(0xfd47fc01, LDRdu(DA_V(1), DA_GP(0), 0xff8));
TEST(0, STRdu(DA_V(1), DA_GP(0), 0xfff));
TEST(0, LDRdu(DA_V(1), DA_GP(0), 0xfff));
TEST(0xfd380001, STRdu(DA_V(1), DA_GP(0), 0x7000));
TEST(0xfd780001, LDRdu(DA_V(1), DA_GP(0), 0x7000));
TEST(0xfd3ffc01, STRdu(DA_V(1), DA_GP(0), 0x7ff8));
TEST(0xfd7ffc01, LDRdu(DA_V(1), DA_GP(0), 0x7ff8));
TEST(0, STRdu(DA_V(1), DA_GP(0), 0x7fff));
TEST(0, LDRdu(DA_V(1), DA_GP(0), 0x7fff));
TEST(0, STRdu(DA_V(1), DA_GP(0), 0x8000));
TEST(0, LDRdu(DA_V(1), DA_GP(0), 0x8000));
TEST(0, STRdu(DA_V(1), DA_GP(0), 0x10000));
TEST(0, LDRdu(DA_V(1), DA_GP(0), 0x10000));
TEST(0, STRqu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRqu(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRqu(DA_V(1), DA_GP(0), -0x1));
TEST(0, LDRqu(DA_V(1), DA_GP(0), -0x1));
TEST(0x3d800001, STRqu(DA_V(1), DA_GP(0), 0));
TEST(0x3dc00001, LDRqu(DA_V(1), DA_GP(0), 0));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0x1));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0x1));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0x2));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0x2));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0x4));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0x4));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0x8));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0x8));
TEST(0x3d800401, STRqu(DA_V(1), DA_GP(0), 0x10));
TEST(0x3dc00401, LDRqu(DA_V(1), DA_GP(0), 0x10));
TEST(0x3d8007e1, STRqu(DA_V(1), DA_SP, 0x10));
TEST(0x3dc007e1, LDRqu(DA_V(1), DA_SP, 0x10));
TEST(0x3d83fc01, STRqu(DA_V(1), DA_GP(0), 0xff0));
TEST(0x3dc3fc01, LDRqu(DA_V(1), DA_GP(0), 0xff0));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0xfff));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0xfff));
TEST(0x3dbc0001, STRqu(DA_V(1), DA_GP(0), 0xf000));
TEST(0x3dfc0001, LDRqu(DA_V(1), DA_GP(0), 0xf000));
TEST(0x3dbffc01, STRqu(DA_V(1), DA_GP(0), 0xfff0));
TEST(0x3dfffc01, LDRqu(DA_V(1), DA_GP(0), 0xfff0));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0xffff));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0xffff));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0x10000));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0x10000));
TEST(0, STRqu(DA_V(1), DA_GP(0), 0x20000));
TEST(0, LDRqu(DA_V(1), DA_GP(0), 0x20000));

// STUR/LDUR and STR/LDR pre/post-indexed
TEST(0, STURb(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDURb(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRb_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRb_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRb_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRb_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STURb(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDURb(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRb_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRb_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRb_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRb_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0x3c100001, STURb(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c500001, LDURb(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c100401, STRb_post(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c500401, LDRb_post(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c100c01, STRb_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c500c01, LDRb_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c101001, STURb(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c501001, LDURb(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c101401, STRb_post(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c501401, LDRb_post(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c101c01, STRb_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c501c01, LDRb_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c1ff001, STURb(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c5ff001, LDURb(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c1ff401, STRb_post(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c5ff401, LDRb_post(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c1ffc01, STRb_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c5ffc01, LDRb_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c000001, STURb(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c400001, LDURb(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c000401, STRb_post(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c400401, LDRb_post(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c000c01, STRb_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c400c01, LDRb_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c0013e1, STURb(DA_V(1), DA_SP, 0x1));
TEST(0x3c4013e1, LDURb(DA_V(1), DA_SP, 0x1));
TEST(0x3c0017e1, STRb_post(DA_V(1), DA_SP, 0x1));
TEST(0x3c4017e1, LDRb_post(DA_V(1), DA_SP, 0x1));
TEST(0x3c001fe1, STRb_pre(DA_V(1), DA_SP, 0x1));
TEST(0x3c401fe1, LDRb_pre(DA_V(1), DA_SP, 0x1));
TEST(0x3c001001, STURb(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c401001, LDURb(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c001401, STRb_post(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c401401, LDRb_post(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c001c01, STRb_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c401c01, LDRb_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c0ff001, STURb(DA_V(1), DA_GP(0), 0xff));
TEST(0x3c4ff001, LDURb(DA_V(1), DA_GP(0), 0xff));
TEST(0x3c0ff401, STRb_post(DA_V(1), DA_GP(0), 0xff));
TEST(0x3c4ff401, LDRb_post(DA_V(1), DA_GP(0), 0xff));
TEST(0x3c0ffc01, STRb_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0x3c4ffc01, LDRb_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0, STURb(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDURb(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRb_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRb_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRb_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRb_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, STURb(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDURb(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRb_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRb_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRb_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRb_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STURh(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDURh(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRh_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRh_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRh_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRh_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STURh(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDURh(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRh_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRh_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRh_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRh_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0x7c100001, STURh(DA_V(1), DA_GP(0), -0x100));
TEST(0x7c500001, LDURh(DA_V(1), DA_GP(0), -0x100));
TEST(0x7c100401, STRh_post(DA_V(1), DA_GP(0), -0x100));
TEST(0x7c500401, LDRh_post(DA_V(1), DA_GP(0), -0x100));
TEST(0x7c100c01, STRh_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0x7c500c01, LDRh_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0x7c101001, STURh(DA_V(1), DA_GP(0), -0xff));
TEST(0x7c501001, LDURh(DA_V(1), DA_GP(0), -0xff));
TEST(0x7c101401, STRh_post(DA_V(1), DA_GP(0), -0xff));
TEST(0x7c501401, LDRh_post(DA_V(1), DA_GP(0), -0xff));
TEST(0x7c101c01, STRh_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0x7c501c01, LDRh_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0x7c1ff001, STURh(DA_V(1), DA_GP(0), -0x1));
TEST(0x7c5ff001, LDURh(DA_V(1), DA_GP(0), -0x1));
TEST(0x7c1ff401, STRh_post(DA_V(1), DA_GP(0), -0x1));
TEST(0x7c5ff401, LDRh_post(DA_V(1), DA_GP(0), -0x1));
TEST(0x7c1ffc01, STRh_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0x7c5ffc01, LDRh_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0x7c000001, STURh(DA_V(1), DA_GP(0), 0x0));
TEST(0x7c400001, LDURh(DA_V(1), DA_GP(0), 0x0));
TEST(0x7c000401, STRh_post(DA_V(1), DA_GP(0), 0x0));
TEST(0x7c400401, LDRh_post(DA_V(1), DA_GP(0), 0x0));
TEST(0x7c000c01, STRh_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0x7c400c01, LDRh_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0x7c0013e1, STURh(DA_V(1), DA_SP, 0x1));
TEST(0x7c4013e1, LDURh(DA_V(1), DA_SP, 0x1));
TEST(0x7c0017e1, STRh_post(DA_V(1), DA_SP, 0x1));
TEST(0x7c4017e1, LDRh_post(DA_V(1), DA_SP, 0x1));
TEST(0x7c001fe1, STRh_pre(DA_V(1), DA_SP, 0x1));
TEST(0x7c401fe1, LDRh_pre(DA_V(1), DA_SP, 0x1));
TEST(0x7c001001, STURh(DA_V(1), DA_GP(0), 0x1));
TEST(0x7c401001, LDURh(DA_V(1), DA_GP(0), 0x1));
TEST(0x7c001401, STRh_post(DA_V(1), DA_GP(0), 0x1));
TEST(0x7c401401, LDRh_post(DA_V(1), DA_GP(0), 0x1));
TEST(0x7c001c01, STRh_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0x7c401c01, LDRh_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0x7c0ff001, STURh(DA_V(1), DA_GP(0), 0xff));
TEST(0x7c4ff001, LDURh(DA_V(1), DA_GP(0), 0xff));
TEST(0x7c0ff401, STRh_post(DA_V(1), DA_GP(0), 0xff));
TEST(0x7c4ff401, LDRh_post(DA_V(1), DA_GP(0), 0xff));
TEST(0x7c0ffc01, STRh_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0x7c4ffc01, LDRh_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0, STURh(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDURh(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRh_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRh_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRh_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRh_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, STURh(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDURh(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRh_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRh_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRh_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRh_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STURs(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDURs(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRs_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRs_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRs_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRs_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STURs(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDURs(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRs_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRs_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRs_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRs_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0xbc100001, STURs(DA_V(1), DA_GP(0), -0x100));
TEST(0xbc500001, LDURs(DA_V(1), DA_GP(0), -0x100));
TEST(0xbc100401, STRs_post(DA_V(1), DA_GP(0), -0x100));
TEST(0xbc500401, LDRs_post(DA_V(1), DA_GP(0), -0x100));
TEST(0xbc100c01, STRs_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0xbc500c01, LDRs_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0xbc101001, STURs(DA_V(1), DA_GP(0), -0xff));
TEST(0xbc501001, LDURs(DA_V(1), DA_GP(0), -0xff));
TEST(0xbc101401, STRs_post(DA_V(1), DA_GP(0), -0xff));
TEST(0xbc501401, LDRs_post(DA_V(1), DA_GP(0), -0xff));
TEST(0xbc101c01, STRs_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0xbc501c01, LDRs_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0xbc1ff001, STURs(DA_V(1), DA_GP(0), -0x1));
TEST(0xbc5ff001, LDURs(DA_V(1), DA_GP(0), -0x1));
TEST(0xbc1ff401, STRs_post(DA_V(1), DA_GP(0), -0x1));
TEST(0xbc5ff401, LDRs_post(DA_V(1), DA_GP(0), -0x1));
TEST(0xbc1ffc01, STRs_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0xbc5ffc01, LDRs_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0xbc000001, STURs(DA_V(1), DA_GP(0), 0x0));
TEST(0xbc400001, LDURs(DA_V(1), DA_GP(0), 0x0));
TEST(0xbc000401, STRs_post(DA_V(1), DA_GP(0), 0x0));
TEST(0xbc400401, LDRs_post(DA_V(1), DA_GP(0), 0x0));
TEST(0xbc000c01, STRs_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0xbc400c01, LDRs_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0xbc0013e1, STURs(DA_V(1), DA_SP, 0x1));
TEST(0xbc4013e1, LDURs(DA_V(1), DA_SP, 0x1));
TEST(0xbc0017e1, STRs_post(DA_V(1), DA_SP, 0x1));
TEST(0xbc4017e1, LDRs_post(DA_V(1), DA_SP, 0x1));
TEST(0xbc001fe1, STRs_pre(DA_V(1), DA_SP, 0x1));
TEST(0xbc401fe1, LDRs_pre(DA_V(1), DA_SP, 0x1));
TEST(0xbc001001, STURs(DA_V(1), DA_GP(0), 0x1));
TEST(0xbc401001, LDURs(DA_V(1), DA_GP(0), 0x1));
TEST(0xbc001401, STRs_post(DA_V(1), DA_GP(0), 0x1));
TEST(0xbc401401, LDRs_post(DA_V(1), DA_GP(0), 0x1));
TEST(0xbc001c01, STRs_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0xbc401c01, LDRs_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0xbc0ff001, STURs(DA_V(1), DA_GP(0), 0xff));
TEST(0xbc4ff001, LDURs(DA_V(1), DA_GP(0), 0xff));
TEST(0xbc0ff401, STRs_post(DA_V(1), DA_GP(0), 0xff));
TEST(0xbc4ff401, LDRs_post(DA_V(1), DA_GP(0), 0xff));
TEST(0xbc0ffc01, STRs_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0xbc4ffc01, LDRs_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0, STURs(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDURs(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRs_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRs_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRs_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRs_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, STURs(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDURs(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRs_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRs_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRs_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRs_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STURd(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDURd(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRd_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRd_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRd_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRd_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STURd(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDURd(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRd_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRd_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRd_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRd_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0xfc100001, STURd(DA_V(1), DA_GP(0), -0x100));
TEST(0xfc500001, LDURd(DA_V(1), DA_GP(0), -0x100));
TEST(0xfc100401, STRd_post(DA_V(1), DA_GP(0), -0x100));
TEST(0xfc500401, LDRd_post(DA_V(1), DA_GP(0), -0x100));
TEST(0xfc100c01, STRd_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0xfc500c01, LDRd_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0xfc101001, STURd(DA_V(1), DA_GP(0), -0xff));
TEST(0xfc501001, LDURd(DA_V(1), DA_GP(0), -0xff));
TEST(0xfc101401, STRd_post(DA_V(1), DA_GP(0), -0xff));
TEST(0xfc501401, LDRd_post(DA_V(1), DA_GP(0), -0xff));
TEST(0xfc101c01, STRd_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0xfc501c01, LDRd_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0xfc1ff001, STURd(DA_V(1), DA_GP(0), -0x1));
TEST(0xfc5ff001, LDURd(DA_V(1), DA_GP(0), -0x1));
TEST(0xfc1ff401, STRd_post(DA_V(1), DA_GP(0), -0x1));
TEST(0xfc5ff401, LDRd_post(DA_V(1), DA_GP(0), -0x1));
TEST(0xfc1ffc01, STRd_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0xfc5ffc01, LDRd_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0xfc000001, STURd(DA_V(1), DA_GP(0), 0x0));
TEST(0xfc400001, LDURd(DA_V(1), DA_GP(0), 0x0));
TEST(0xfc000401, STRd_post(DA_V(1), DA_GP(0), 0x0));
TEST(0xfc400401, LDRd_post(DA_V(1), DA_GP(0), 0x0));
TEST(0xfc000c01, STRd_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0xfc400c01, LDRd_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0xfc0013e1, STURd(DA_V(1), DA_SP, 0x1));
TEST(0xfc4013e1, LDURd(DA_V(1), DA_SP, 0x1));
TEST(0xfc0017e1, STRd_post(DA_V(1), DA_SP, 0x1));
TEST(0xfc4017e1, LDRd_post(DA_V(1), DA_SP, 0x1));
TEST(0xfc001fe1, STRd_pre(DA_V(1), DA_SP, 0x1));
TEST(0xfc401fe1, LDRd_pre(DA_V(1), DA_SP, 0x1));
TEST(0xfc001001, STURd(DA_V(1), DA_GP(0), 0x1));
TEST(0xfc401001, LDURd(DA_V(1), DA_GP(0), 0x1));
TEST(0xfc001401, STRd_post(DA_V(1), DA_GP(0), 0x1));
TEST(0xfc401401, LDRd_post(DA_V(1), DA_GP(0), 0x1));
TEST(0xfc001c01, STRd_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0xfc401c01, LDRd_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0xfc0ff001, STURd(DA_V(1), DA_GP(0), 0xff));
TEST(0xfc4ff001, LDURd(DA_V(1), DA_GP(0), 0xff));
TEST(0xfc0ff401, STRd_post(DA_V(1), DA_GP(0), 0xff));
TEST(0xfc4ff401, LDRd_post(DA_V(1), DA_GP(0), 0xff));
TEST(0xfc0ffc01, STRd_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0xfc4ffc01, LDRd_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0, STURd(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDURd(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRd_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRd_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRd_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRd_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, STURd(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDURd(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRd_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRd_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRd_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRd_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STURq(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDURq(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRq_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRq_post(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STRq_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, LDRq_pre(DA_V(1), DA_GP(0), -0x1000));
TEST(0, STURq(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDURq(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRq_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRq_post(DA_V(1), DA_GP(0), -0x101));
TEST(0, STRq_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0, LDRq_pre(DA_V(1), DA_GP(0), -0x101));
TEST(0x3c900001, STURq(DA_V(1), DA_GP(0), -0x100));
TEST(0x3cd00001, LDURq(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c900401, STRq_post(DA_V(1), DA_GP(0), -0x100));
TEST(0x3cd00401, LDRq_post(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c900c01, STRq_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0x3cd00c01, LDRq_pre(DA_V(1), DA_GP(0), -0x100));
TEST(0x3c901001, STURq(DA_V(1), DA_GP(0), -0xff));
TEST(0x3cd01001, LDURq(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c901401, STRq_post(DA_V(1), DA_GP(0), -0xff));
TEST(0x3cd01401, LDRq_post(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c901c01, STRq_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0x3cd01c01, LDRq_pre(DA_V(1), DA_GP(0), -0xff));
TEST(0x3c9ff001, STURq(DA_V(1), DA_GP(0), -0x1));
TEST(0x3cdff001, LDURq(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c9ff401, STRq_post(DA_V(1), DA_GP(0), -0x1));
TEST(0x3cdff401, LDRq_post(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c9ffc01, STRq_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0x3cdffc01, LDRq_pre(DA_V(1), DA_GP(0), -0x1));
TEST(0x3c800001, STURq(DA_V(1), DA_GP(0), 0x0));
TEST(0x3cc00001, LDURq(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c800401, STRq_post(DA_V(1), DA_GP(0), 0x0));
TEST(0x3cc00401, LDRq_post(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c800c01, STRq_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0x3cc00c01, LDRq_pre(DA_V(1), DA_GP(0), 0x0));
TEST(0x3c8013e1, STURq(DA_V(1), DA_SP, 0x1));
TEST(0x3cc013e1, LDURq(DA_V(1), DA_SP, 0x1));
TEST(0x3c8017e1, STRq_post(DA_V(1), DA_SP, 0x1));
TEST(0x3cc017e1, LDRq_post(DA_V(1), DA_SP, 0x1));
TEST(0x3c801fe1, STRq_pre(DA_V(1), DA_SP, 0x1));
TEST(0x3cc01fe1, LDRq_pre(DA_V(1), DA_SP, 0x1));
TEST(0x3c801001, STURq(DA_V(1), DA_GP(0), 0x1));
TEST(0x3cc01001, LDURq(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c801401, STRq_post(DA_V(1), DA_GP(0), 0x1));
TEST(0x3cc01401, LDRq_post(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c801c01, STRq_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0x3cc01c01, LDRq_pre(DA_V(1), DA_GP(0), 0x1));
TEST(0x3c8ff001, STURq(DA_V(1), DA_GP(0), 0xff));
TEST(0x3ccff001, LDURq(DA_V(1), DA_GP(0), 0xff));
TEST(0x3c8ff401, STRq_post(DA_V(1), DA_GP(0), 0xff));
TEST(0x3ccff401, LDRq_post(DA_V(1), DA_GP(0), 0xff));
TEST(0x3c8ffc01, STRq_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0x3ccffc01, LDRq_pre(DA_V(1), DA_GP(0), 0xff));
TEST(0, STURq(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDURq(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRq_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRq_post(DA_V(1), DA_GP(0), 0x100));
TEST(0, STRq_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, LDRq_pre(DA_V(1), DA_GP(0), 0x100));
TEST(0, STURq(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDURq(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRq_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRq_post(DA_V(1), DA_GP(0), 0x1000));
TEST(0, STRq_pre(DA_V(1), DA_GP(0), 0x1000));
TEST(0, LDRq_pre(DA_V(1), DA_GP(0), 0x1000));
