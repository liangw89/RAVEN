// save for copyright

#include <core.p4>
#include <tna.p4>

#include "header.h"
#include "parser.h"


// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
        

        Hash<bit<32>>(HashAlgorithm_t.CRC32) calc_cksum;
        Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy1;

        action drop() {
            eg_intr_dprs_md.drop_ctl = 0x1; // Drop packet.
        }

        apply {

            eg_md.tag = calc_cksum.get({SUB_NET, hdr.ipv6.dst_addr, hdr.ipv6.src_sub, 
                hdr.ipv6.src_addr, hdr.udp.dst_port, hdr.udp.src_port});

            if (eg_md.is_dec) {
                eg_md.tag_hi = copy1.get(eg_md.tag[31:16]);

                // if (eg_md.tag_hi == hdr.ipv6.dst_sub[31:16]) 
                if (true){

                   hdr.ipv6.dst_sub = SUB_NET;
                   hdr.ipv6.dst_prex = NET_PREFIX;
                   hdr.ethernet.dst_addr = 48w0x0c42a1dd5990;
                   // hdr.ethernet.dst_addr =   48w0xbc97e17e9a90;
                }
                else {
                    drop();
                }
            }

        }

}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------


control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    Random<bit<8>>() rng1;
    Random<bit<8>>() rng2;
    Random<bit<8>>() rng3;
    Random<bit<32>>() rng_l;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) calc_cksum;
    Random<bit<6>>() rng4;
    
    Hash<bit<2>>(HashAlgorithm_t.IDENTITY) copy_ver;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_ip1;
    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_ip2;

    Hash<bit<32>>(HashAlgorithm_t.IDENTITY) copy_rnd_t;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd1;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd2;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd3;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy_rnd4;

    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_1;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_2;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_3;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_4;

    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_11;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_22;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_33;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_44;

    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_111;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_222;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_333;
    Hash<bit<8>>(HashAlgorithm_t.IDENTITY) copy8_444;

    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy_16_1;
    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy_16_2;

    Hash<bit<4>>(HashAlgorithm_t.IDENTITY) copy_slice_1;
    Hash<bit<4>>(HashAlgorithm_t.IDENTITY) copy_slice_2;
    action nop() {
        
    }

    //-------------------------------
    // SBOX and reverse SBOX
    //-------------------------------
    #define SBOX(NAME, KEY, DO) table NAME {\
        key= {KEY:exact;}\
        actions = {DO; nop;}\
        const entries = {0:DO(0x63); 1:DO(0x7c); 2:DO(0x77); 3:DO(0x7b); 4:DO(0xf2); 5:DO(0x6b); 6:DO(0x6f); 7:DO(0xc5); \
            8:DO(0x30); 9:DO(0x1); 10:DO(0x67); 11:DO(0x2b); 12:DO(0xfe); 13:DO(0xd7); 14:DO(0xab); 15:DO(0x76); \
            16:DO(0xca); 17:DO(0x82); 18:DO(0xc9); 19:DO(0x7d); 20:DO(0xfa); 21:DO(0x59); 22:DO(0x47); 23:DO(0xf0); \
            24:DO(0xad); 25:DO(0xd4); 26:DO(0xa2); 27:DO(0xaf); 28:DO(0x9c); 29:DO(0xa4); 30:DO(0x72); 31:DO(0xc0); \
            32:DO(0xb7); 33:DO(0xfd); 34:DO(0x93); 35:DO(0x26); 36:DO(0x36); 37:DO(0x3f); 38:DO(0xf7); 39:DO(0xcc); \
            40:DO(0x34); 41:DO(0xa5); 42:DO(0xe5); 43:DO(0xf1); 44:DO(0x71); 45:DO(0xd8); 46:DO(0x31); 47:DO(0x15); \
            48:DO(0x4); 49:DO(0xc7); 50:DO(0x23); 51:DO(0xc3); 52:DO(0x18); 53:DO(0x96); 54:DO(0x5); 55:DO(0x9a); \
            56:DO(0x7); 57:DO(0x12); 58:DO(0x80); 59:DO(0xe2); 60:DO(0xeb); 61:DO(0x27); 62:DO(0xb2); 63:DO(0x75); \
            64:DO(0x9); 65:DO(0x83); 66:DO(0x2c); 67:DO(0x1a); 68:DO(0x1b); 69:DO(0x6e); 70:DO(0x5a); 71:DO(0xa0); \
            72:DO(0x52); 73:DO(0x3b); 74:DO(0xd6); 75:DO(0xb3); 76:DO(0x29); 77:DO(0xe3); 78:DO(0x2f); 79:DO(0x84); \
            80:DO(0x53); 81:DO(0xd1); 82:DO(0x0); 83:DO(0xed); 84:DO(0x20); 85:DO(0xfc); 86:DO(0xb1); 87:DO(0x5b); \
            88:DO(0x6a); 89:DO(0xcb); 90:DO(0xbe); 91:DO(0x39); 92:DO(0x4a); 93:DO(0x4c); 94:DO(0x58); 95:DO(0xcf); \
            96:DO(0xd0); 97:DO(0xef); 98:DO(0xaa); 99:DO(0xfb); 100:DO(0x43); 101:DO(0x4d); 102:DO(0x33); 103:DO(0x85); \
            104:DO(0x45); 105:DO(0xf9); 106:DO(0x2); 107:DO(0x7f); 108:DO(0x50); 109:DO(0x3c); 110:DO(0x9f); 111:DO(0xa8); \
            112:DO(0x51); 113:DO(0xa3); 114:DO(0x40); 115:DO(0x8f); 116:DO(0x92); 117:DO(0x9d); 118:DO(0x38); 119:DO(0xf5); \
            120:DO(0xbc); 121:DO(0xb6); 122:DO(0xda); 123:DO(0x21); 124:DO(0x10); 125:DO(0xff); 126:DO(0xf3); 127:DO(0xd2); \
            128:DO(0xcd); 129:DO(0xc); 130:DO(0x13); 131:DO(0xec); 132:DO(0x5f); 133:DO(0x97); 134:DO(0x44); 135:DO(0x17); \
            136:DO(0xc4); 137:DO(0xa7); 138:DO(0x7e); 139:DO(0x3d); 140:DO(0x64); 141:DO(0x5d); 142:DO(0x19); 143:DO(0x73); \
            144:DO(0x60); 145:DO(0x81); 146:DO(0x4f); 147:DO(0xdc); 148:DO(0x22); 149:DO(0x2a); 150:DO(0x90); 151:DO(0x88); \
            152:DO(0x46); 153:DO(0xee); 154:DO(0xb8); 155:DO(0x14); 156:DO(0xde); 157:DO(0x5e); 158:DO(0xb); 159:DO(0xdb); \
            160:DO(0xe0); 161:DO(0x32); 162:DO(0x3a); 163:DO(0xa); 164:DO(0x49); 165:DO(0x6); 166:DO(0x24); 167:DO(0x5c); \
            168:DO(0xc2); 169:DO(0xd3); 170:DO(0xac); 171:DO(0x62); 172:DO(0x91); 173:DO(0x95); 174:DO(0xe4); 175:DO(0x79); \
            176:DO(0xe7); 177:DO(0xc8); 178:DO(0x37); 179:DO(0x6d); 180:DO(0x8d); 181:DO(0xd5); 182:DO(0x4e); 183:DO(0xa9); \
            184:DO(0x6c); 185:DO(0x56); 186:DO(0xf4); 187:DO(0xea); 188:DO(0x65); 189:DO(0x7a); 190:DO(0xae); 191:DO(0x8); \
            192:DO(0xba); 193:DO(0x78); 194:DO(0x25); 195:DO(0x2e); 196:DO(0x1c); 197:DO(0xa6); 198:DO(0xb4); 199:DO(0xc6); \
            200:DO(0xe8); 201:DO(0xdd); 202:DO(0x74); 203:DO(0x1f); 204:DO(0x4b); 205:DO(0xbd); 206:DO(0x8b); 207:DO(0x8a); \
            208:DO(0x70); 209:DO(0x3e); 210:DO(0xb5); 211:DO(0x66); 212:DO(0x48); 213:DO(0x3); 214:DO(0xf6); 215:DO(0xe); \
            216:DO(0x61); 217:DO(0x35); 218:DO(0x57); 219:DO(0xb9); 220:DO(0x86); 221:DO(0xc1); 222:DO(0x1d); 223:DO(0x9e); \
            224:DO(0xe1); 225:DO(0xf8); 226:DO(0x98); 227:DO(0x11); 228:DO(0x69); 229:DO(0xd9); 230:DO(0x8e); 231:DO(0x94); \
            232:DO(0x9b); 233:DO(0x1e); 234:DO(0x87); 235:DO(0xe9); 236:DO(0xce); 237:DO(0x55); 238:DO(0x28); 239:DO(0xdf); \
            240:DO(0x8c); 241:DO(0xa1); 242:DO(0x89); 243:DO(0xd); 244:DO(0xbf); 245:DO(0xe6); 246:DO(0x42); 247:DO(0x68); \
            248:DO(0x41); 249:DO(0x99); 250:DO(0x2d); 251:DO(0xf); 252:DO(0xb0); 253:DO(0x54); 254:DO(0xbb); 255:DO(0x16); }\
        size = 256; \
        const default_action = nop; \
    }


    #define RSBOX(NAME, KEY, DO) table NAME { \
        key= {KEY:exact;}\
        actions = {DO; nop;}\
        const entries = {0:DO(0x52); 1:DO(0x9); 2:DO(0x6a); 3:DO(0xd5); 4:DO(0x30); 5:DO(0x36); 6:DO(0xa5); 7:DO(0x38); \
            8:DO(0xbf); 9:DO(0x40); 10:DO(0xa3); 11:DO(0x9e); 12:DO(0x81); 13:DO(0xf3); 14:DO(0xd7); 15:DO(0xfb); \
            16:DO(0x7c); 17:DO(0xe3); 18:DO(0x39); 19:DO(0x82); 20:DO(0x9b); 21:DO(0x2f); 22:DO(0xff); 23:DO(0x87); \
            24:DO(0x34); 25:DO(0x8e); 26:DO(0x43); 27:DO(0x44); 28:DO(0xc4); 29:DO(0xde); 30:DO(0xe9); 31:DO(0xcb); \
            32:DO(0x54); 33:DO(0x7b); 34:DO(0x94); 35:DO(0x32); 36:DO(0xa6); 37:DO(0xc2); 38:DO(0x23); 39:DO(0x3d); \
            40:DO(0xee); 41:DO(0x4c); 42:DO(0x95); 43:DO(0xb); 44:DO(0x42); 45:DO(0xfa); 46:DO(0xc3); 47:DO(0x4e); \
            48:DO(0x8); 49:DO(0x2e); 50:DO(0xa1); 51:DO(0x66); 52:DO(0x28); 53:DO(0xd9); 54:DO(0x24); 55:DO(0xb2); \
            56:DO(0x76); 57:DO(0x5b); 58:DO(0xa2); 59:DO(0x49); 60:DO(0x6d); 61:DO(0x8b); 62:DO(0xd1); 63:DO(0x25); \
            64:DO(0x72); 65:DO(0xf8); 66:DO(0xf6); 67:DO(0x64); 68:DO(0x86); 69:DO(0x68); 70:DO(0x98); 71:DO(0x16); \
            72:DO(0xd4); 73:DO(0xa4); 74:DO(0x5c); 75:DO(0xcc); 76:DO(0x5d); 77:DO(0x65); 78:DO(0xb6); 79:DO(0x92); \
            80:DO(0x6c); 81:DO(0x70); 82:DO(0x48); 83:DO(0x50); 84:DO(0xfd); 85:DO(0xed); 86:DO(0xb9); 87:DO(0xda); \
            88:DO(0x5e); 89:DO(0x15); 90:DO(0x46); 91:DO(0x57); 92:DO(0xa7); 93:DO(0x8d); 94:DO(0x9d); 95:DO(0x84); \
            96:DO(0x90); 97:DO(0xd8); 98:DO(0xab); 99:DO(0x0); 100:DO(0x8c); 101:DO(0xbc); 102:DO(0xd3); 103:DO(0xa); \
            104:DO(0xf7); 105:DO(0xe4); 106:DO(0x58); 107:DO(0x5); 108:DO(0xb8); 109:DO(0xb3); 110:DO(0x45); 111:DO(0x6); \
            112:DO(0xd0); 113:DO(0x2c); 114:DO(0x1e); 115:DO(0x8f); 116:DO(0xca); 117:DO(0x3f); 118:DO(0xf); 119:DO(0x2); \
            120:DO(0xc1); 121:DO(0xaf); 122:DO(0xbd); 123:DO(0x3); 124:DO(0x1); 125:DO(0x13); 126:DO(0x8a); 127:DO(0x6b); \
            128:DO(0x3a); 129:DO(0x91); 130:DO(0x11); 131:DO(0x41); 132:DO(0x4f); 133:DO(0x67); 134:DO(0xdc); 135:DO(0xea); \
            136:DO(0x97); 137:DO(0xf2); 138:DO(0xcf); 139:DO(0xce); 140:DO(0xf0); 141:DO(0xb4); 142:DO(0xe6); 143:DO(0x73); \
            144:DO(0x96); 145:DO(0xac); 146:DO(0x74); 147:DO(0x22); 148:DO(0xe7); 149:DO(0xad); 150:DO(0x35); 151:DO(0x85); \
            152:DO(0xe2); 153:DO(0xf9); 154:DO(0x37); 155:DO(0xe8); 156:DO(0x1c); 157:DO(0x75); 158:DO(0xdf); 159:DO(0x6e); \
            160:DO(0x47); 161:DO(0xf1); 162:DO(0x1a); 163:DO(0x71); 164:DO(0x1d); 165:DO(0x29); 166:DO(0xc5); 167:DO(0x89); \
            168:DO(0x6f); 169:DO(0xb7); 170:DO(0x62); 171:DO(0xe); 172:DO(0xaa); 173:DO(0x18); 174:DO(0xbe); 175:DO(0x1b); \
            176:DO(0xfc); 177:DO(0x56); 178:DO(0x3e); 179:DO(0x4b); 180:DO(0xc6); 181:DO(0xd2); 182:DO(0x79); 183:DO(0x20); \
            184:DO(0x9a); 185:DO(0xdb); 186:DO(0xc0); 187:DO(0xfe); 188:DO(0x78); 189:DO(0xcd); 190:DO(0x5a); 191:DO(0xf4); \
            192:DO(0x1f); 193:DO(0xdd); 194:DO(0xa8); 195:DO(0x33); 196:DO(0x88); 197:DO(0x7); 198:DO(0xc7); 199:DO(0x31); \
            200:DO(0xb1); 201:DO(0x12); 202:DO(0x10); 203:DO(0x59); 204:DO(0x27); 205:DO(0x80); 206:DO(0xec); 207:DO(0x5f); \
            208:DO(0x60); 209:DO(0x51); 210:DO(0x7f); 211:DO(0xa9); 212:DO(0x19); 213:DO(0xb5); 214:DO(0x4a); 215:DO(0xd); \
            216:DO(0x2d); 217:DO(0xe5); 218:DO(0x7a); 219:DO(0x9f); 220:DO(0x93); 221:DO(0xc9); 222:DO(0x9c); 223:DO(0xef); \
            224:DO(0xa0); 225:DO(0xe0); 226:DO(0x3b); 227:DO(0x4d); 228:DO(0xae); 229:DO(0x2a); 230:DO(0xf5); 231:DO(0xb0); \
            232:DO(0xc8); 233:DO(0xeb); 234:DO(0xbb); 235:DO(0x3c); 236:DO(0x83); 237:DO(0x53); 238:DO(0x99); 239:DO(0x61); \
            240:DO(0x17); 241:DO(0x2b); 242:DO(0x4); 243:DO(0x7e); 244:DO(0xba); 245:DO(0x77); 246:DO(0xd6); 247:DO(0x26); \
            248:DO(0xe1); 249:DO(0x69); 250:DO(0x14); 251:DO(0x63); 252:DO(0x55); 253:DO(0x21); 254:DO(0xc); 255:DO(0x7d);}\        
        size = 256; \
        const default_action = nop; \
    }


    //-------------------------------
    // SBOX and reverse SBOX actions
    //-------------------------------

    #define SBOXACTION(NAME, OUT, IN)  action NAME(bit<8> value){\
        OUT = value ^ IN; \ 
     }

    #define RSBOXACTION(NAME, OUT)  action NAME(bit<8> value){\
        OUT = value; \ 
    }

    //-------------------------------
    // identity hash for bit copy
    //-------------------------------

    #define BITH_1(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy1_##NO##;

    #define BITH_2(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy2_##NO##; 

    #define BITH_3(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy3_##NO##;

    #define BITH_4(NO) Hash<bit<1>>(HashAlgorithm_t.IDENTITY) copy4_##NO##;

    #define INIT_BITH(NO) BITH_##NO##(1) BITH_##NO##(2) BITH_##NO##(3) BITH_##NO##(4) BITH_##NO##(5) BITH_##NO##(6) BITH_##NO##(7) BITH_##NO##(8) \    
    BITH_##NO##(9) BITH_##NO##(10) BITH_##NO##(11) BITH_##NO##(12) BITH_##NO##(13) BITH_##NO##(14) BITH_##NO##(15) BITH_##NO##(16) \
    BITH_##NO##(17) BITH_##NO##(18) BITH_##NO##(19) BITH_##NO##(20) BITH_##NO##(21) BITH_##NO##(22) BITH_##NO##(23) BITH_##NO##(24) \
    BITH_##NO##(25) BITH_##NO##(26) BITH_##NO##(27) BITH_##NO##(28) BITH_##NO##(29) BITH_##NO##(30) BITH_##NO##(31) BITH_##NO##(32) \
    BITH_##NO##(33) BITH_##NO##(34) BITH_##NO##(35) BITH_##NO##(36) BITH_##NO##(37) BITH_##NO##(38) BITH_##NO##(39) BITH_##NO##(40) \
    BITH_##NO##(41) BITH_##NO##(42) BITH_##NO##(43) BITH_##NO##(44) BITH_##NO##(45) BITH_##NO##(46) BITH_##NO##(47) BITH_##NO##(48) \
    BITH_##NO##(49) BITH_##NO##(50) BITH_##NO##(51) BITH_##NO##(52) BITH_##NO##(53) BITH_##NO##(54) BITH_##NO##(55) BITH_##NO##(56) \
    BITH_##NO##(57) BITH_##NO##(58) BITH_##NO##(59) BITH_##NO##(60) BITH_##NO##(61) BITH_##NO##(62) BITH_##NO##(63) BITH_##NO##(64)


    INIT_BITH(1)
    INIT_BITH(2)
    INIT_BITH(3)
    INIT_BITH(4)

    
    // init sbox and reverse sbox actions

    SBOXACTION(S1, ig_md.c1, ig_md.otp1[31:24])
    SBOXACTION(S2, ig_md.c2, ig_md.otp1[23:16])
    SBOXACTION(S3, ig_md.c3, ig_md.otp1[15:8])
    SBOXACTION(S4, ig_md.c4, ig_md.otp1[7:0])
    SBOXACTION(S5, ig_md.r1, ig_md.otp1[63:56])
    SBOXACTION(S6, ig_md.r2, ig_md.otp1[55:48])
    SBOXACTION(S7, ig_md.r3, ig_md.otp1[47:40])
    SBOXACTION(S8, ig_md.r4, ig_md.otp1[39:32])

    SBOX(SBOX1, ig_md.c1, S1)
    SBOX(SBOX2, ig_md.c2, S2)
    SBOX(SBOX3, ig_md.c3, S3)
    SBOX(SBOX4, ig_md.c4, S4)
    SBOX(SBOX5, ig_md.r1, S5)
    SBOX(SBOX6, ig_md.r2, S6)
    SBOX(SBOX7, ig_md.r3, S7)
    SBOX(SBOX8, ig_md.r4, S8)
    

    SBOXACTION(S11, ig_md.c1, ig_md.otp2[31:24])
    SBOXACTION(S22, ig_md.c2, ig_md.otp2[23:16])
    SBOXACTION(S33, ig_md.c3, ig_md.otp2[15:8])
    SBOXACTION(S44, ig_md.c4, ig_md.otp2[7:0])
    SBOXACTION(S55, ig_md.r1, ig_md.otp2[63:56])
    SBOXACTION(S66, ig_md.r2, ig_md.otp2[55:48])
    SBOXACTION(S77, ig_md.r3, ig_md.otp2[47:40])
    SBOXACTION(S88, ig_md.r4, ig_md.otp2[39:32])


    SBOX(SBOX11, ig_md.c1, S11)
    SBOX(SBOX22, ig_md.c2, S22)
    SBOX(SBOX33, ig_md.c3, S33)
    SBOX(SBOX44, ig_md.c4, S44)
    SBOX(SBOX55, ig_md.r1, S55)
    SBOX(SBOX66, ig_md.r2, S66)
    SBOX(SBOX77, ig_md.r3, S77)
    SBOX(SBOX88, ig_md.r4, S88)


    RSBOXACTION(RS1, ig_md.c1)
    RSBOXACTION(RS2, ig_md.c2)
    RSBOXACTION(RS3, ig_md.c3)
    RSBOXACTION(RS4, ig_md.c4)
    RSBOXACTION(RS5, ig_md.r1)
    RSBOXACTION(RS6, ig_md.r2)
    RSBOXACTION(RS7, ig_md.r3)
    RSBOXACTION(RS8, ig_md.r4)

    RSBOX(RSBOX1, ig_md.c1, RS1)
    RSBOX(RSBOX2, ig_md.c2, RS2)
    RSBOX(RSBOX3, ig_md.c3, RS3)
    RSBOX(RSBOX4, ig_md.c4, RS4)
    RSBOX(RSBOX5, ig_md.r1, RS5)
    RSBOX(RSBOX6, ig_md.r2, RS6)
    RSBOX(RSBOX7, ig_md.r3, RS7)
    RSBOX(RSBOX8, ig_md.r4, RS8)

    SBOXACTION(RS11, ig_md.c1, ig_md.otp2[31:24])
    SBOXACTION(RS22, ig_md.c2, ig_md.otp2[23:16])
    SBOXACTION(RS33, ig_md.c3, ig_md.otp2[15:8])
    SBOXACTION(RS44, ig_md.c4, ig_md.otp2[7:0])
    SBOXACTION(RS55, ig_md.r1, ig_md.otp2[63:56])
    SBOXACTION(RS66, ig_md.r2, ig_md.otp2[55:48])
    SBOXACTION(RS77, ig_md.r3, ig_md.otp2[47:40])
    SBOXACTION(RS88, ig_md.r4, ig_md.otp2[39:32])


    RSBOX(RSBOX11, ig_md.c1, RS11)
    RSBOX(RSBOX22, ig_md.c2, RS22)
    RSBOX(RSBOX33, ig_md.c3, RS33)
    RSBOX(RSBOX44, ig_md.c4, RS44)
    RSBOX(RSBOX55, ig_md.r1, RS55)
    RSBOX(RSBOX66, ig_md.r2, RS66)
    RSBOX(RSBOX77, ig_md.r3, RS77)
    RSBOX(RSBOX88, ig_md.r4, RS88)


    // set the lowest 32 bits of the encrypted IPv6 source address
    // or set the decrypted IPv4 destination address
    action set_final_ip(bool is_enc) {
        if (is_enc) {
           
            hdr.ipv6.src_addr[31:31] = copy1_32.get(ig_md.c4[0:0]);
            hdr.ipv6.src_addr[30:30] = copy1_27.get(ig_md.c4[5:5]);
            hdr.ipv6.src_addr[29:29] = copy1_11.get(ig_md.c2[5:5]);
            hdr.ipv6.src_addr[28:28] = copy1_16.get(ig_md.c2[0:0]);
            hdr.ipv6.src_addr[27:27] = copy1_4.get(ig_md.c1[4:4]);
            hdr.ipv6.src_addr[26:26] = copy1_54.get(ig_md.r3[2:2]);
            hdr.ipv6.src_addr[25:25] = copy1_36.get(ig_md.r1[4:4]);
            hdr.ipv6.src_addr[24:24] = copy1_28.get(ig_md.c4[4:4]);
            hdr.ipv6.src_addr[23:23] = copy1_61.get(ig_md.r4[3:3]);
            hdr.ipv6.src_addr[22:22] = copy1_30.get(ig_md.c4[2:2]);
            hdr.ipv6.src_addr[21:21] = copy1_44.get(ig_md.r2[4:4]);
            hdr.ipv6.src_addr[20:20] = copy1_23.get(ig_md.c3[1:1]);
            hdr.ipv6.src_addr[19:19] = copy1_20.get(ig_md.c3[4:4]);
            hdr.ipv6.src_addr[18:18] = copy1_17.get(ig_md.c3[7:7]);
            hdr.ipv6.src_addr[17:17] = copy1_64.get(ig_md.r4[0:0]);
            hdr.ipv6.src_addr[16:16] = copy1_29.get(ig_md.c4[3:3]);
            hdr.ipv6.src_addr[15:15] = copy1_34.get(ig_md.r1[6:6]);
            hdr.ipv6.src_addr[14:14] = copy1_21.get(ig_md.c3[3:3]);
            hdr.ipv6.src_addr[13:13] = copy1_52.get(ig_md.r3[4:4]);
            hdr.ipv6.src_addr[12:12] = copy1_50.get(ig_md.r3[6:6]);
            hdr.ipv6.src_addr[11:11] = copy1_13.get(ig_md.c2[3:3]);
            hdr.ipv6.src_addr[10:10] = copy1_9.get(ig_md.c2[7:7]);
            hdr.ipv6.src_addr[9:9] = copy1_18.get(ig_md.c3[6:6]);
            hdr.ipv6.src_addr[8:8] = copy1_3.get(ig_md.c1[5:5]);
            hdr.ipv6.src_addr[7:7] = copy1_56.get(ig_md.r3[0:0]);
            hdr.ipv6.src_addr[6:6] = copy1_62.get(ig_md.r4[2:2]);
            hdr.ipv6.src_addr[5:5] = copy1_19.get(ig_md.c3[5:5]);
            hdr.ipv6.src_addr[4:4] = copy1_15.get(ig_md.c2[1:1]);
            hdr.ipv6.src_addr[3:3] = copy1_45.get(ig_md.r2[3:3]);
            hdr.ipv6.src_addr[2:2] = copy1_7.get(ig_md.c1[1:1]);
            hdr.ipv6.src_addr[1:1] = copy1_48.get(ig_md.r2[0:0]);
            hdr.ipv6.src_addr[0:0] = copy1_57.get(ig_md.r4[7:7]);


        } else {
            hdr.ipv6.dst_addr[31:24] = copy8_1.get(ig_md.c1);
            hdr.ipv6.dst_addr[23:16] = copy8_2.get(ig_md.c2);
            hdr.ipv6.dst_addr[15:8] = copy8_3.get(ig_md.c3);
            hdr.ipv6.dst_addr[7:0] = copy8_4.get(ig_md.c4);
        }

    }

    // set the subnet part of the encrypted IPv6 source address
    action set_final_sub(bool is_enc) {
        if (is_enc) {
            hdr.ipv6.src_sub[31:31] = copy1_35.get(ig_md.r1[5:5]);
            hdr.ipv6.src_sub[30:30] = copy1_12.get(ig_md.c2[4:4]);
            hdr.ipv6.src_sub[29:29] = copy1_22.get(ig_md.c3[2:2]);
            hdr.ipv6.src_sub[28:28] = copy1_40.get(ig_md.r1[0:0]);
            hdr.ipv6.src_sub[27:27] = copy1_39.get(ig_md.r1[1:1]);
            hdr.ipv6.src_sub[26:26] = copy1_8.get(ig_md.c1[0:0]);
            hdr.ipv6.src_sub[25:25] = copy1_60.get(ig_md.r4[4:4]);
            hdr.ipv6.src_sub[24:24] = copy1_47.get(ig_md.r2[1:1]);
            hdr.ipv6.src_sub[23:23] = copy1_31.get(ig_md.c4[1:1]);
            hdr.ipv6.src_sub[22:22] = copy1_14.get(ig_md.c2[2:2]);
            hdr.ipv6.src_sub[21:21] = copy1_55.get(ig_md.r3[1:1]);
            hdr.ipv6.src_sub[20:20] = copy1_2.get(ig_md.c1[6:6]);
            hdr.ipv6.src_sub[19:19] = copy1_37.get(ig_md.r1[3:3]);
            hdr.ipv6.src_sub[18:18] = copy1_58.get(ig_md.r4[6:6]);
            hdr.ipv6.src_sub[17:17] = copy1_6.get(ig_md.c1[2:2]);
            hdr.ipv6.src_sub[16:16] = copy1_43.get(ig_md.r2[5:5]);

            hdr.udp.src_port[15:15] = copy1_25.get(ig_md.c4[7:7]);
            hdr.udp.src_port[14:14] = copy1_10.get(ig_md.c2[6:6]);
            hdr.udp.src_port[13:13] = copy1_33.get(ig_md.r1[7:7]);
            hdr.udp.src_port[12:12] = copy1_26.get(ig_md.c4[6:6]);
            hdr.udp.src_port[11:11] = copy1_41.get(ig_md.r2[7:7]);
            hdr.udp.src_port[10:10] = copy1_24.get(ig_md.c3[0:0]);
            hdr.udp.src_port[9:9] = copy1_53.get(ig_md.r3[3:3]);
            hdr.udp.src_port[8:8] = copy1_42.get(ig_md.r2[6:6]);
            hdr.udp.src_port[7:7] = copy1_5.get(ig_md.c1[3:3]);
            hdr.udp.src_port[6:6] = copy1_59.get(ig_md.r4[5:5]);
            hdr.udp.src_port[5:5] = copy1_46.get(ig_md.r2[2:2]);
            hdr.udp.src_port[4:4] = copy1_1.get(ig_md.c1[7:7]);
            hdr.udp.src_port[3:3] = copy1_38.get(ig_md.r1[2:2]);
            hdr.udp.src_port[2:2] = copy1_51.get(ig_md.r3[5:5]);
            hdr.udp.src_port[1:1] = copy1_49.get(ig_md.r3[7:7]);
            hdr.udp.src_port[0:0] = copy1_63.get(ig_md.r4[1:1]);

        } else {    
            // pass
            // hdr.ipv6.dst_sub = SUB_NET;
            hdr.ipv6.dst_sub[31:24] = copy8_111.get(ig_md.r1);
            hdr.ipv6.dst_sub[23:16] = copy8_222.get(ig_md.r2);
            hdr.udp.dst_port[15:8] = copy8_333.get(ig_md.r3);
            hdr.udp.dst_port[7:0] = copy8_444.get(ig_md.r4);
        } 


    }
        

    // if encryption: generate random padding
    // if decryption: copy the subnet part in an encrypted address
    action gen_rnd(bool is_enc) {
        if (is_enc) {
            // ig_md.new_rnd = rng_l.get();
            ig_md.new_rnd = calc_cksum.get({hdr.ipv6.src_sub, hdr.ipv6.src_addr, hdr.ipv6.dst_sub, 
                hdr.ipv6.dst_addr, hdr.udp.src_port, hdr.udp.dst_port}) ^ ig_md.conn_id;
            

        } else {
            ig_md.new_rnd1[31:31] = copy2_51.get(hdr.udp.dst_port[13:13]);
            ig_md.new_rnd1[30:30] = copy2_17.get(hdr.ipv6.dst_addr[15:15]);
            ig_md.new_rnd1[29:29] = copy2_33.get(hdr.ipv6.dst_sub[31:31]);
            ig_md.new_rnd1[28:28] = copy2_7.get(hdr.ipv6.dst_addr[25:25]);
            ig_md.new_rnd1[27:27] = copy2_45.get(hdr.ipv6.dst_sub[19:19]);
            ig_md.new_rnd1[26:26] = copy2_61.get(hdr.udp.dst_port[3:3]);
            ig_md.new_rnd1[25:25] = copy2_37.get(hdr.ipv6.dst_sub[27:27]);
            ig_md.new_rnd1[24:24] = copy2_36.get(hdr.ipv6.dst_sub[28:28]);
            ig_md.new_rnd1[23:23] = copy2_53.get(hdr.udp.dst_port[11:11]);
            ig_md.new_rnd1[22:22] = copy2_56.get(hdr.udp.dst_port[8:8]);
            ig_md.new_rnd1[21:21] = copy2_48.get(hdr.ipv6.dst_sub[16:16]);
            ig_md.new_rnd1[20:20] = copy2_11.get(hdr.ipv6.dst_addr[21:21]);
            ig_md.new_rnd1[19:19] = copy2_29.get(hdr.ipv6.dst_addr[3:3]);
            ig_md.new_rnd1[18:18] = copy2_59.get(hdr.udp.dst_port[5:5]);
            ig_md.new_rnd1[17:17] = copy2_40.get(hdr.ipv6.dst_sub[24:24]);
            ig_md.new_rnd1[16:16] = copy2_31.get(hdr.ipv6.dst_addr[1:1]);
            ig_md.new_rnd1[15:15] = copy2_63.get(hdr.udp.dst_port[1:1]);
            ig_md.new_rnd1[14:14] = copy2_20.get(hdr.ipv6.dst_addr[12:12]);
            ig_md.new_rnd1[13:13] = copy2_62.get(hdr.udp.dst_port[2:2]);
            ig_md.new_rnd1[12:12] = copy2_19.get(hdr.ipv6.dst_addr[13:13]);
            ig_md.new_rnd1[11:11] = copy2_55.get(hdr.udp.dst_port[9:9]);
            ig_md.new_rnd1[10:10] = copy2_6.get(hdr.ipv6.dst_addr[26:26]);
            ig_md.new_rnd1[9:9] = copy2_43.get(hdr.ipv6.dst_sub[21:21]);
            ig_md.new_rnd1[8:8] = copy2_25.get(hdr.ipv6.dst_addr[7:7]);
            ig_md.new_rnd1[7:7] = copy2_32.get(hdr.ipv6.dst_addr[0:0]);
            ig_md.new_rnd1[6:6] = copy2_46.get(hdr.ipv6.dst_sub[18:18]);
            ig_md.new_rnd1[5:5] = copy2_58.get(hdr.udp.dst_port[6:6]);
            ig_md.new_rnd1[4:4] = copy2_39.get(hdr.ipv6.dst_sub[25:25]);
            ig_md.new_rnd1[3:3] = copy2_9.get(hdr.ipv6.dst_addr[23:23]);
            ig_md.new_rnd1[2:2] = copy2_26.get(hdr.ipv6.dst_addr[6:6]);
            ig_md.new_rnd1[1:1] = copy2_64.get(hdr.udp.dst_port[0:0]);
            ig_md.new_rnd1[0:0] = copy2_15.get(hdr.ipv6.dst_addr[17:17]);
        }       
    }

    // permutation for 63-32 bits 
    action p1(){
         hdr.ipv6.src_addr[31:31] = copy3_22.get(ig_md.c3[2:2]);
        hdr.ipv6.src_addr[30:30] = copy3_15.get(ig_md.c2[1:1]);
        hdr.ipv6.src_addr[29:29] = copy3_50.get(ig_md.r3[6:6]);
        hdr.ipv6.src_addr[28:28] = copy3_6.get(ig_md.c1[2:2]);
        hdr.ipv6.src_addr[27:27] = copy3_17.get(ig_md.c3[7:7]);
        hdr.ipv6.src_addr[26:26] = copy3_57.get(ig_md.r4[7:7]);
        hdr.ipv6.src_addr[25:25] = copy3_59.get(ig_md.r4[5:5]);
        hdr.ipv6.src_addr[24:24] = copy3_25.get(ig_md.c4[7:7]);
        hdr.ipv6.src_addr[23:23] = copy3_34.get(ig_md.r1[6:6]);
        hdr.ipv6.src_addr[22:22] = copy3_7.get(ig_md.c1[1:1]);
        hdr.ipv6.src_addr[21:21] = copy3_1.get(ig_md.c1[7:7]);
        hdr.ipv6.src_addr[20:20] = copy3_20.get(ig_md.c3[4:4]);
        hdr.ipv6.src_addr[19:19] = copy3_24.get(ig_md.c3[0:0]);
        hdr.ipv6.src_addr[18:18] = copy3_4.get(ig_md.c1[4:4]);
        hdr.ipv6.src_addr[17:17] = copy3_28.get(ig_md.c4[4:4]);
        hdr.ipv6.src_addr[16:16] = copy3_30.get(ig_md.c4[2:2]);
        hdr.ipv6.src_addr[15:15] = copy3_43.get(ig_md.r2[5:5]);
        hdr.ipv6.src_addr[14:14] = copy3_11.get(ig_md.c2[5:5]);
        hdr.ipv6.src_addr[13:13] = copy3_8.get(ig_md.c1[0:0]);
        hdr.ipv6.src_addr[12:12] = copy3_61.get(ig_md.r4[3:3]);
        hdr.ipv6.src_addr[11:11] = copy3_39.get(ig_md.r1[1:1]);
        hdr.ipv6.src_addr[10:10] = copy3_38.get(ig_md.r1[2:2]);
        hdr.ipv6.src_addr[9:9] = copy3_56.get(ig_md.r3[0:0]);
        hdr.ipv6.src_addr[8:8] = copy3_52.get(ig_md.r3[4:4]);
        hdr.ipv6.src_addr[7:7] = copy3_31.get(ig_md.c4[1:1]);
        hdr.ipv6.src_addr[6:6] = copy3_47.get(ig_md.r2[1:1]);
        hdr.ipv6.src_addr[5:5] = copy3_35.get(ig_md.r1[5:5]);
        hdr.ipv6.src_addr[4:4] = copy3_62.get(ig_md.r4[2:2]);
        hdr.ipv6.src_addr[3:3] = copy3_23.get(ig_md.c3[1:1]);
        hdr.ipv6.src_addr[2:2] = copy3_33.get(ig_md.r1[7:7]);
        hdr.ipv6.src_addr[1:1] = copy3_48.get(ig_md.r2[0:0]);
        hdr.ipv6.src_addr[0:0] = copy3_42.get(ig_md.r2[6:6]);
    }
    
    // permutation for 31-0 bits 
    action p2(){
        hdr.ipv6.src_sub[31:31] = copy3_64.get(ig_md.r4[0:0]);
        hdr.ipv6.src_sub[30:30] = copy3_19.get(ig_md.c3[5:5]);
        hdr.ipv6.src_sub[29:29] = copy3_5.get(ig_md.c1[3:3]);
        hdr.ipv6.src_sub[28:28] = copy3_14.get(ig_md.c2[2:2]);
        hdr.ipv6.src_sub[27:27] = copy3_26.get(ig_md.c4[6:6]);
        hdr.ipv6.src_sub[26:26] = copy3_29.get(ig_md.c4[3:3]);
        hdr.ipv6.src_sub[25:25] = copy3_36.get(ig_md.r1[4:4]);
        hdr.ipv6.src_sub[24:24] = copy3_21.get(ig_md.c3[3:3]);
        hdr.ipv6.src_sub[23:23] = copy3_46.get(ig_md.r2[2:2]);
        hdr.ipv6.src_sub[22:22] = copy3_55.get(ig_md.r3[1:1]);
        hdr.ipv6.src_sub[21:21] = copy3_18.get(ig_md.c3[6:6]);
        hdr.ipv6.src_sub[20:20] = copy3_3.get(ig_md.c1[5:5]);
        hdr.ipv6.src_sub[19:19] = copy3_27.get(ig_md.c4[5:5]);
        hdr.ipv6.src_sub[18:18] = copy3_51.get(ig_md.r3[5:5]);
        hdr.ipv6.src_sub[17:17] = copy3_58.get(ig_md.r4[6:6]);
        hdr.ipv6.src_sub[16:16] = copy3_16.get(ig_md.c2[0:0]);
        hdr.ipv6.src_sub[15:15] = copy3_60.get(ig_md.r4[4:4]);
        hdr.ipv6.src_sub[14:14] = copy3_32.get(ig_md.c4[0:0]);
        hdr.ipv6.src_sub[13:13] = copy3_41.get(ig_md.r2[7:7]);
        hdr.ipv6.src_sub[12:12] = copy3_44.get(ig_md.r2[4:4]);
        hdr.ipv6.src_sub[11:11] = copy3_12.get(ig_md.c2[4:4]);
        hdr.ipv6.src_sub[10:10] = copy3_40.get(ig_md.r1[0:0]);
        hdr.ipv6.src_sub[9:9] = copy3_49.get(ig_md.r3[7:7]);
        hdr.ipv6.src_sub[8:8] = copy3_10.get(ig_md.c2[6:6]);
        hdr.ipv6.src_sub[7:7] = copy3_54.get(ig_md.r3[2:2]);
        hdr.ipv6.src_sub[6:6] = copy3_45.get(ig_md.r2[3:3]);
        hdr.ipv6.src_sub[5:5] = copy3_53.get(ig_md.r3[3:3]);
        hdr.ipv6.src_sub[4:4] = copy3_2.get(ig_md.c1[6:6]);
        hdr.ipv6.src_sub[3:3] = copy3_9.get(ig_md.c2[7:7]);
        hdr.ipv6.src_sub[2:2] = copy3_13.get(ig_md.c2[3:3]);
        hdr.ipv6.src_sub[1:1] = copy3_37.get(ig_md.r1[3:3]);
        hdr.ipv6.src_sub[0:0] = copy3_63.get(ig_md.r4[1:1]);
    }
    
    // reverse permutation for 63-32 bits 
    action rp1(){
        ig_md.new_ip[31:31] = copy4_11.get(ig_md.c2[5:5]);
        ig_md.new_ip[30:30] = copy4_60.get(ig_md.r4[4:4]);
        ig_md.new_ip[29:29] = copy4_44.get(ig_md.r2[4:4]);
        ig_md.new_ip[28:28] = copy4_14.get(ig_md.c2[2:2]);
        ig_md.new_ip[27:27] = copy4_35.get(ig_md.r1[5:5]);
        ig_md.new_ip[26:26] = copy4_4.get(ig_md.c1[4:4]);
        ig_md.new_ip[25:25] = copy4_10.get(ig_md.c2[6:6]);
        ig_md.new_ip[24:24] = copy4_19.get(ig_md.c3[5:5]);
        ig_md.new_ip[23:23] = copy4_61.get(ig_md.r4[3:3]);
        ig_md.new_ip[22:22] = copy4_56.get(ig_md.r3[0:0]);
        ig_md.new_ip[21:21] = copy4_18.get(ig_md.c3[6:6]);
        ig_md.new_ip[20:20] = copy4_53.get(ig_md.r3[3:3]);
        ig_md.new_ip[19:19] = copy4_62.get(ig_md.r4[2:2]);
        ig_md.new_ip[18:18] = copy4_36.get(ig_md.r1[4:4]);
        ig_md.new_ip[17:17] = copy4_2.get(ig_md.c1[6:6]);
        ig_md.new_ip[16:16] = copy4_48.get(ig_md.r2[0:0]);
        ig_md.new_ip[15:15] = copy4_5.get(ig_md.c1[3:3]);
        ig_md.new_ip[14:14] = copy4_43.get(ig_md.r2[5:5]);
        ig_md.new_ip[13:13] = copy4_34.get(ig_md.r1[6:6]);
        ig_md.new_ip[12:12] = copy4_12.get(ig_md.c2[4:4]);
        ig_md.new_ip[11:11] = copy4_40.get(ig_md.r1[0:0]);
        ig_md.new_ip[10:10] = copy4_1.get(ig_md.c1[7:7]);
        ig_md.new_ip[9:9] = copy4_29.get(ig_md.c4[3:3]);
        ig_md.new_ip[8:8] = copy4_13.get(ig_md.c2[3:3]);
        ig_md.new_ip[7:7] = copy4_8.get(ig_md.c1[0:0]);
        ig_md.new_ip[6:6] = copy4_37.get(ig_md.r1[3:3]);
        ig_md.new_ip[5:5] = copy4_45.get(ig_md.r2[3:3]);
        ig_md.new_ip[4:4] = copy4_15.get(ig_md.c2[1:1]);
        ig_md.new_ip[3:3] = copy4_38.get(ig_md.r1[2:2]);
        ig_md.new_ip[2:2] = copy4_16.get(ig_md.c2[0:0]);
        ig_md.new_ip[1:1] = copy4_25.get(ig_md.c4[7:7]);
        ig_md.new_ip[0:0] = copy4_50.get(ig_md.r3[6:6]);
    }
    
    // reverse permutation for 31-0 bits
    action rp2(){
        ig_md.new_rnd1[31:31] = copy4_30.get(ig_md.c4[2:2]);
        ig_md.new_rnd1[30:30] = copy4_9.get(ig_md.c2[7:7]);
        ig_md.new_rnd1[29:29] = copy4_27.get(ig_md.c4[5:5]);
        ig_md.new_rnd1[28:28] = copy4_39.get(ig_md.r1[1:1]);
        ig_md.new_rnd1[27:27] = copy4_63.get(ig_md.r4[1:1]);
        ig_md.new_rnd1[26:26] = copy4_22.get(ig_md.c3[2:2]);
        ig_md.new_rnd1[25:25] = copy4_21.get(ig_md.c3[3:3]);
        ig_md.new_rnd1[24:24] = copy4_54.get(ig_md.r3[2:2]);
        ig_md.new_rnd1[23:23] = copy4_51.get(ig_md.r3[5:5]);
        ig_md.new_rnd1[22:22] = copy4_32.get(ig_md.c4[0:0]);
        ig_md.new_rnd1[21:21] = copy4_17.get(ig_md.c3[7:7]);
        ig_md.new_rnd1[20:20] = copy4_52.get(ig_md.r3[4:4]);
        ig_md.new_rnd1[19:19] = copy4_58.get(ig_md.r4[6:6]);
        ig_md.new_rnd1[18:18] = copy4_41.get(ig_md.r2[7:7]);
        ig_md.new_rnd1[17:17] = copy4_26.get(ig_md.c4[6:6]);
        ig_md.new_rnd1[16:16] = copy4_31.get(ig_md.c4[1:1]);
        ig_md.new_rnd1[15:15] = copy4_55.get(ig_md.r3[1:1]);
        ig_md.new_rnd1[14:14] = copy4_3.get(ig_md.c1[5:5]);
        ig_md.new_rnd1[13:13] = copy4_46.get(ig_md.r2[2:2]);
        ig_md.new_rnd1[12:12] = copy4_24.get(ig_md.c3[0:0]);
        ig_md.new_rnd1[11:11] = copy4_59.get(ig_md.r4[5:5]);
        ig_md.new_rnd1[10:10] = copy4_57.get(ig_md.r4[7:7]);
        ig_md.new_rnd1[9:9] = copy4_42.get(ig_md.r2[6:6]);
        ig_md.new_rnd1[8:8] = copy4_23.get(ig_md.c3[1:1]);
        ig_md.new_rnd1[7:7] = copy4_6.get(ig_md.c1[2:2]);
        ig_md.new_rnd1[6:6] = copy4_47.get(ig_md.r2[1:1]);
        ig_md.new_rnd1[5:5] = copy4_7.get(ig_md.c1[1:1]);
        ig_md.new_rnd1[4:4] = copy4_49.get(ig_md.r3[7:7]);
        ig_md.new_rnd1[3:3] = copy4_20.get(ig_md.c3[4:4]);
        ig_md.new_rnd1[2:2] = copy4_28.get(ig_md.c4[4:4]);
        ig_md.new_rnd1[1:1] = copy4_64.get(ig_md.r4[0:0]);
        ig_md.new_rnd1[0:0] = copy4_33.get(ig_md.r1[7:7]);
    }

    action copy_ip() {
        ig_md.new_ip = copy_ip1.get(hdr.ipv6.src_addr);
    }

    action copy_ip_r() { 
        ig_md.new_ip[31:31] = copy2_60.get(hdr.udp.dst_port[4:4]);
        ig_md.new_ip[30:30] = copy2_44.get(hdr.ipv6.dst_sub[20:20]);
        ig_md.new_ip[29:29] = copy2_24.get(hdr.ipv6.dst_addr[8:8]);
        ig_md.new_ip[28:28] = copy2_5.get(hdr.ipv6.dst_addr[27:27]);
        ig_md.new_ip[27:27] = copy2_57.get(hdr.udp.dst_port[7:7]);
        ig_md.new_ip[26:26] = copy2_47.get(hdr.ipv6.dst_sub[17:17]);
        ig_md.new_ip[25:25] = copy2_30.get(hdr.ipv6.dst_addr[2:2]);
        ig_md.new_ip[24:24] = copy2_38.get(hdr.ipv6.dst_sub[26:26]);
        ig_md.new_ip[23:23] = copy2_22.get(hdr.ipv6.dst_addr[10:10]);
        ig_md.new_ip[22:22] = copy2_50.get(hdr.udp.dst_port[14:14]);
        ig_md.new_ip[21:21] = copy2_3.get(hdr.ipv6.dst_addr[29:29]);
        ig_md.new_ip[20:20] = copy2_34.get(hdr.ipv6.dst_sub[30:30]);
        ig_md.new_ip[19:19] = copy2_21.get(hdr.ipv6.dst_addr[11:11]);
        ig_md.new_ip[18:18] = copy2_42.get(hdr.ipv6.dst_sub[22:22]);
        ig_md.new_ip[17:17] = copy2_28.get(hdr.ipv6.dst_addr[4:4]);
        ig_md.new_ip[16:16] = copy2_4.get(hdr.ipv6.dst_addr[28:28]);
        ig_md.new_ip[15:15] = copy2_14.get(hdr.ipv6.dst_addr[18:18]);
        ig_md.new_ip[14:14] = copy2_23.get(hdr.ipv6.dst_addr[9:9]);
        ig_md.new_ip[13:13] = copy2_27.get(hdr.ipv6.dst_addr[5:5]);
        ig_md.new_ip[12:12] = copy2_13.get(hdr.ipv6.dst_addr[19:19]);
        ig_md.new_ip[11:11] = copy2_18.get(hdr.ipv6.dst_addr[14:14]);
        ig_md.new_ip[10:10] = copy2_35.get(hdr.ipv6.dst_sub[29:29]);
        ig_md.new_ip[9:9] = copy2_12.get(hdr.ipv6.dst_addr[20:20]);
        ig_md.new_ip[8:8] = copy2_54.get(hdr.udp.dst_port[10:10]);
        ig_md.new_ip[7:7] = copy2_49.get(hdr.udp.dst_port[15:15]);
        ig_md.new_ip[6:6] = copy2_52.get(hdr.udp.dst_port[12:12]);
        ig_md.new_ip[5:5] = copy2_2.get(hdr.ipv6.dst_addr[30:30]);
        ig_md.new_ip[4:4] = copy2_8.get(hdr.ipv6.dst_addr[24:24]);
        ig_md.new_ip[3:3] = copy2_16.get(hdr.ipv6.dst_addr[16:16]);
        ig_md.new_ip[2:2] = copy2_10.get(hdr.ipv6.dst_addr[22:22]);
        ig_md.new_ip[1:1] = copy2_41.get(hdr.ipv6.dst_sub[23:23]);
        ig_md.new_ip[0:0] = copy2_1.get(hdr.ipv6.dst_addr[31:31]);

    }
    action init_lookup_key_ip(bool is_enc){
        if (is_enc) {
            ig_md.c1 = ig_md.new_ip[31:24];
            ig_md.c2 = ig_md.new_ip[23:16];
            ig_md.c3 = ig_md.new_ip[15:8];
            ig_md.c4 = ig_md.new_ip[7:0];

        } else {
            ig_md.c1 = ig_md.new_ip[31:24];
            ig_md.c2 = ig_md.new_ip[23:16];
            ig_md.c3 = ig_md.new_ip[15:8];
            ig_md.c4 = ig_md.new_ip[7:0]; 
        }
    }

    action init_lookup_key_rnd(bool is_enc) {
        if (is_enc) {
            ig_md.r1 = hdr.ipv6.src_sub[31:24];
            ig_md.r2 = hdr.ipv6.src_sub[23:16];
            ig_md.r3 = hdr.ipv6.src_sub[15:8];
            ig_md.r4 = hdr.ipv6.src_sub[7:0];
        } else {
            ig_md.r1 = copy8_11.get(ig_md.new_rnd1[31:24]);
            ig_md.r2 = copy8_22.get(ig_md.new_rnd1[23:16]);
            ig_md.r3 = copy8_33.get(ig_md.new_rnd1[15:8]);
            ig_md.r4 = copy8_44.get(ig_md.new_rnd1[7:0]);
        }

    }

    action init_pkt_n1(bool is_enc) {
        ig_md.otp1 = 0x0;
        ig_md.otp2 = 0x0;
        ig_md.new_ip1 = 0x0;
        ig_md.is_set_sub = false;

        if (is_enc) {  
            hdr.ipv6.src_prex = PUB_NET_PREFIX;
        } else {
            ig_md.cur_ver =  hdr.ipv6.dst_sub[1:0];
        
        }
        
    }


    action get_key_1(bit<32> k1, bit<32> k2, bit<64> otp1, bit<64> otp2) {
        ig_md.new_ip = ig_md.new_ip ^ k1;
        ig_md.new_rnd = ig_md.new_rnd ^ k2;
        ig_md.otp1 = otp1;
        ig_md.otp2 = otp2;
    }


    table xor_with_key_1 {
        key = {
            ig_md.cur_ver: exact;
            ig_md.slice1: exact;
        }
        actions = {
                get_key_1;
                nop;
            }
        size = 64;
        default_action = nop();
    }

    action get_key_2(bit<32> k1, bit<32> k2, bit<64> otp1, bit<64> otp2) {
        ig_md.new_ip = ig_md.new_ip ^ k1;
        ig_md.new_rnd1 = ig_md.new_rnd1 ^ k2;
        ig_md.otp1 = otp1;
        ig_md.otp2 = otp2;
    }


    table xor_with_key_2 {
        key = {
            ig_md.cur_ver: exact;
            ig_md.slice2: exact;
        }
        actions = {
                get_key_2;
                nop;
            }
        size = 64;
        default_action = nop();
    }


    action port_enc_act(bit<16> tmpk) {
        hdr.udp.src_port = hdr.udp.src_port ^ tmpk;
        hdr.tcp.src_port = hdr.tcp.src_port ^ tmpk;

    }

    table port_enc {
        key = {
            ig_md.r1: exact;
            ig_md.cur_ver: exact;
        }
        actions = {
            port_enc_act;
            nop;
        }
        size = 1024;
    }

    action port_dec_act(bit<16> tmpk) {
        hdr.udp.dst_port = hdr.udp.dst_port ^ tmpk;
        hdr.tcp.dst_port = hdr.tcp.dst_port ^ tmpk;
        
    }

    table  port_dec {
        key = {
            ig_md.r1: exact;
            ig_md.cur_ver: exact;
        }
        actions = {
            port_dec_act;
            nop;
        }
        size = 1024;
    }

    action hit(PortId_t port, bit<2> ver) {
        ig_intr_tm_md.ucast_egress_port = port;
        ig_md.cur_ver = ver;
    }


    table forward {
            key = {
                ig_intr_md.ingress_port: exact;        
            }
            actions = {
                hit;
                nop;
            }
            size = 128;
            default_action = nop();
    }


    action switchPort(PortId_t port) {
                ig_intr_tm_md.ucast_egress_port = port;
    }
        
   table forward_exc1 {
          key = {
                 hdr.ipv4.src_addr: exact; 
                 // hdr.tcp.src_port: exact; 
          }
          actions = {
                 switchPort;
                 nop;
          }
         size = 4;
         default_action = nop();
   }
   
    table forward_exc2 {
          key = {
                 hdr.ipv4.dst_addr: exact; 
                 hdr.tcp.dst_port: exact; 
          }
          actions = {
                 switchPort;
                 nop;
          }
         size = 4;
         default_action = nop();
         const entries = {
           (0x80708a98, 0x16) : switchPort(138);
         }
   }
   

    apply {
        
        forward.apply();
        // forward_exc1.apply();
        // forward_exc2.apply();
        //ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port; // reflect, for debugging
        
        if (hdr.udp.isValid() || hdr.tcp.isValid() ) {

            if (ig_md.is_enc) {
                
                /*
                  E = P2 ( P1 ( M xor K1 ) xor K2 ) xor K3
                  = Pa ( S ( Pb ( S ( M xor K1 ) ) xor K2 ) ) xor K3
                  Rewrite this to: 
                  S ( Pa ( Pb ( S ( M xor K1 xor K2 ) ) ) ) xor K3
                */


                ig_md.slice1 = copy_slice_1.get(hdr.ipv6.dst_addr[3:0]) & ig_md.mask;

                copy_ip();
                
                gen_rnd(true); 
                ig_md.new_rnd[15:0] = hdr.udp.src_port;
                
                init_pkt_n1(true);
                xor_with_key_1.apply();

                // inner permutation
                hdr.ipv6.src_sub = copy_rnd_t.get(ig_md.new_rnd);

                init_lookup_key_rnd(true);
                init_lookup_key_ip(true);
                SBOX1.apply(); SBOX2.apply(); SBOX3.apply(); SBOX4.apply();
                SBOX5.apply(); SBOX6.apply(); 
                SBOX7.apply(); SBOX8.apply();
                p1(); p2();

                // outer permutation
                ig_md.new_ip = copy_ip2.get(hdr.ipv6.src_addr);
                init_lookup_key_rnd(true);
                init_lookup_key_ip(true);
                SBOX11.apply(); SBOX22.apply(); SBOX33.apply(); SBOX44.apply();
                SBOX55.apply(); SBOX66.apply(); 
                SBOX77.apply(); SBOX88.apply();


                // note: bit shuffling happens here
                set_final_ip(true);
                set_final_sub(true);
                hdr.ipv6.src_sub[1:0] = copy_ver.get(ig_md.cur_ver);
               

                
            } else if (ig_md.is_dec) {

                ig_md.slice2 = copy_slice_2.get(hdr.ipv6.src_addr[3:0]) & ig_md.mask;

                copy_ip_r();
                gen_rnd(false);

                init_pkt_n1(false);
                
                xor_with_key_2.apply();

                init_lookup_key_rnd(false);
                init_lookup_key_ip(false);
                RSBOX1.apply(); RSBOX2.apply(); RSBOX3.apply(); RSBOX4.apply();
                RSBOX5.apply(); RSBOX6.apply(); 
                RSBOX7.apply(); RSBOX8.apply();
                
                rp1(); rp2();

                ig_md.new_ip = ig_md.new_ip ^ ig_md.otp1[31:0];
                ig_md.new_rnd1 = ig_md.new_rnd1 ^ ig_md.otp1[63:32];
                init_lookup_key_rnd(false);
                init_lookup_key_ip(false);
                RSBOX11.apply(); RSBOX22.apply(); RSBOX33.apply(); RSBOX44.apply();
                RSBOX55.apply(); RSBOX66.apply(); 
                RSBOX77.apply(); RSBOX88.apply();


                set_final_ip(false); 
                set_final_sub(false);
                
            } else {
                // do something else
            }

        } 

    } 

}





Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
         ) pipe;

Switch(pipe) main;
