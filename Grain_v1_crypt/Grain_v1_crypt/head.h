#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <tchar.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <io.h>
#include <direct.h>
#include <ctime>
#include <math.h>
#include <vector>
#include <bitset>
#include <algorithm>
#include <string>
#include <windows.h>




using namespace std;

using std::cin;
using std::cout;
using std::cerr;
using std::string;
using std::endl;
using std::ends;
using std::istream;
using std::ostream;
using std::vector;

//读取某个路径下的所有文件
//#ifndef FUNC_H
//#define FUNC_H
vector<string> & get_filelist(char *foldname);
//#endif
/*
unsigned int NFSR_feedBackFunc();
unsigned int LFSR_feedBackFunc();
void keyInit();
unsigned int filter_func_h();
unsigned int func_h(unsigned int X0,unsigned int X1,unsigned int X2,unsigned int X3,unsigned int X4);
void state_update(bool isInit,unsigned output);
unsigned int* KSGenerator(unsigned int bitLen);
*/

typedef unsigned int u32;
typedef unsigned char u8;

//reduced version of Grain
#define MAX_KSD 2000
#define MAX_KSD_HM 8 
#define KSLen_Reduced 4
#define SP 11
#define STATE_REDUCE 64
#define STATE_BYTE 8
#define STATE_NUM 8192  //对每一组差分随机选择的状态的个数
#define DATA_SET 17		//线上阶段的数据量2的幂次
#define DIR_REDUCE_V2 "D:\\小琦\\Grain_Reduce\\NCA_2.0\\"
#define DIR_REDUCE_TEST_V2 "D:\\小琦\\Grain_Reduce\\NCA_2.0_TEST\\"
#define DIR_REDUCE_V1 "D:\\小琦\\Grain_Reduce\\NCA_1.0\\"
#define DIR_REDUCE_V3 "D:\\小琦\\Grain_Reduce\\NCA_3.0\\"
#define DIR_REDUCE_V3_ASS "D:\\小琦\\Grain_Reduce\\NCA_3.0_ASS\\"

#define DIR_REDUCE_TEST_V3 "D:\\小琦\\Grain_Reduce\\NCA_3.0_TEST\\"
#define DIR_ASS "D:\\小琦\\Grain\\NCA_3.0_ASS\\"
#define FILE_SUFFIX "_imp_rand"
#define WITH_PREFIX "_with_prefix"
#define NO_PREFIX "_without_prefix"
typedef struct{
	u32 LFSR[32];
	u32 NFSR[32];
	const u8* p_key;
	u32 keysize;
	u32 ivsize;
} ECRYPT_ctx_reduce;
typedef struct{
	u8 KS[KSLen_Reduced];
	unsigned long long clock_t;
	u8 state[STATE_REDUCE];
} Online_Data_Reduce;

#ifndef GRAIN_REDUCED_H
#define INITCLOCKS_REDUCED 64
#define N_R(i) (ctx_reduce->NFSR[32-i])
#define L_R(i) (ctx_reduce->LFSR[32-i])
#define X0_R (ctx_reduce->LFSR[3])
#define X1_R (ctx_reduce->LFSR[11])
#define X2_R (ctx_reduce->LFSR[21])
#define X3_R (ctx_reduce->LFSR[25])
#define X4_R (ctx_reduce->NFSR[24])
#endif

void ECRYPT_init_reduce();
void ECRYPT_keysetup_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize);                /* IV size in bits. */ 

void ECRYPT_ivsetup_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* iv);
void ECRYPT_encrypt_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /* Message length in bytes. */ 

void ECRYPT_decrypt_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);                /* Message length in bytes. */ 

#define ECRYPT_GENERATES_KEYSTREAM_REDUCED
#ifdef ECRYPT_GENERATES_KEYSTREAM_REDUCED

void ECRYPT_keystream_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce,
  u8* keystream,
  u32 length);                /* Length of keystream in bytes. */

#endif

//for backward keystream generate
#define ECRYPT_GENERATES_BACKWARD_KEYSTREAM_REDUCED
#ifdef ECRYPT_GENERATES_BACKWARD_KEYSTREAM_REDUCED
void ECRYPT_keystream_backward_bytes_reduce(
  ECRYPT_ctx_reduce* ctx_reduce, 
  u8* keystream, 
  u32 msglen);
#endif

void grain_state_load_reduce(ECRYPT_ctx_reduce* ctx_reduce, u8* state);
void grain_state_read_reduce(ECRYPT_ctx_reduce* ctx_reduce, u8* state);
u8 grain_keystream_backward_reduce(ECRYPT_ctx_reduce* ctx_reduce);
u8 grain_keystream_reduce(ECRYPT_ctx_reduce* ctx_reduce);
//grain reduced sampling resistance
void grain_reduce_sampling_resistance(ECRYPT_ctx_reduce* ctx_reduce,
	u32 *L,u32 *N);
void grain_reduce_sampling_resistance_genKSBytes(ECRYPT_ctx_reduce* ctx_reduce,
  u8* keystream,
  u32 length);
//NAC-2.0 offline table construct
void offLine_table_construct(u32 d);
void combination_for_search_grain_reduce(u32 n,u32 k,string curr_DIR);
bool combin_for_search_imp_sub_grain_reduce(u32 k,u32* v,string curr_DIR);
void genOutput_diff_imp_grain_reduce(u32 k,u32 *v,string curr_DIR);
void stateBit2Byte(u8 *stateByte,u32 byteLen,u32 *LFSR,u32 *NFSR,u32 bitLen);
//NCA-1.0 offline table construct
void offLine_table_construct_v1(u32 d);
void combination_for_search_grain_reduce_v1(u32 n,u32 k,u32 d);
bool combin_for_search_imp_sub_grain_reduce_v1(u32 k,u32* v,u32 d);
void genOutput_diff_imp_grain_reduce_v1(u32 k,u32 *v,u32 d);
//NCA-3.0 offline table construct
void offLine_table_construct_v3(u32 d);
void combination_for_search_grain_reduce_v3(u32 n,u32 k,string curr_DIR);
bool combin_for_search_imp_sub_grain_reduce_v3(u32 k,u32* v,string curr_DIR);
void genOutput_diff_imp_grain_reduce_v3(u32 k,u32 *v,string curr_DIR);
u32 Hamming_weight_of_state(u8* state,u32 Len);
//NCA-1.0 online attack
bool online_attack(); 
bool collect_sets(ECRYPT_ctx_reduce* ctx_reduce,u32 b,double size);
bool find_near_collision(Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size);
//NCA-2.0 online attack
bool online_attack_v2(u32 d);
void collect_sets_v2_no_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,u32 b,unsigned long long set_size);
bool find_near_collision_v2_no_prefix(Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size);
void collect_sets_v2_with_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,u32 b,unsigned long long set_size);
bool find_near_collision_v2_with_prefix(u32 d,Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size);
bool find_near_collision_v2_with_prefix_imp(u32 d,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,unsigned long long set_size);
//NCA-2.0 test
void analyze_collected_data_v2(u32 d);
void compare_find_match(string dir_1,string dir_2);
//NCA-3.0 online attack
bool online_attack_v3(u32 d);
void collect_sets_v3_no_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,u32 b,unsigned long long set_size);
bool find_near_collision_v3_no_prefix(Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size);
bool find_collision_sub_routine(string KSD,string tableName, Online_Data_Reduce *data_A
	,Online_Data_Reduce *data_B,unsigned long long set_size);
bool find_collision_sub_routine_imp(string KSD,string tableName, Online_Data_Reduce *data_A
	,Online_Data_Reduce *data_B,unsigned long long set_size);
long long find_begin(Online_Data_Reduce *data_B,long long i,long long j,Online_Data_Reduce val);
long long find_end(Online_Data_Reduce *data_B,long long i,long long j,Online_Data_Reduce val);
void collect_sets_v3_with_prefix(ECRYPT_ctx_reduce* ctx_reduce,Online_Data_Reduce *data_A,
	Online_Data_Reduce *data_B,u32 b,unsigned long long set_size);
bool find_near_collision_v3_with_prefix(u32 d,Online_Data_Reduce *data_A,Online_Data_Reduce *data_B,unsigned long long set_size);
//NCA-3.0 verify assumption
void verify_assumption(u32 d,u32 random_test_num);
void verify_assumption_reduce(u32 d,u32 random_test_num);
//NCA-3.0 test
void analyze_collected_data(u32 d);
//timer
void start_cal();
void end_cal(double *time);
//random test
void test_time_genOutput_v1();
void test_time_genOutput_v2();
void test_time_genOutput_v3();
//RC4 random generate
void rc4_setup();
u8 rc4();
void randomIV(u32 *iv);
int intcmp(const void *v1, const void *v2);



//grain full version

typedef struct
{
	u32 LFSR[80];
	u32 NFSR[80];
	const u8* p_key;
	u32 keysize;
	u32 ivsize;

} ECRYPT_ctx;

#ifndef GRAIN_H
#define INITCLOCKS 160
#define N(i) (ctx->NFSR[80-i])
#define L(i) (ctx->LFSR[80-i])
#define X0 (ctx->LFSR[3])
#define X1 (ctx->LFSR[25])
#define X2 (ctx->LFSR[46])
#define X3 (ctx->LFSR[64])
#define X4 (ctx->NFSR[63])

static const u8 NFTable[1024]= {0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,0,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,1,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,1,0,1,
								1,0,1,1,0,1,0,0,0,0,0,1,1,1,1,0,0,1,0,0,1,0,1,1,1,1,1,0,1,1,1,1,
								0,1,0,0,1,0,1,1,1,1,1,0,0,0,0,1,0,1,0,0,1,0,1,1,1,1,1,0,1,1,1,1,
								1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,0,1,1,0,1,0,0,0,1,0,0,1,0,1,1,1,0,1,1,1,0,1,0,
								0,1,0,0,1,0,1,1,1,1,1,0,0,0,0,1,1,0,1,1,0,1,0,0,0,0,0,1,0,0,0,0,
								1,0,1,1,0,1,0,0,0,0,0,1,1,1,1,0,1,0,1,1,0,1,0,0,0,0,0,1,1,1,1,1,
								0,1,0,0,1,0,0,0,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,
								1,0,1,1,0,1,1,1,0,1,0,0,1,0,0,0,1,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,
								1,0,1,1,0,1,1,1,0,0,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,1,1,0,1,1,0,0,
								0,1,0,0,1,0,0,0,1,1,1,0,0,0,1,0,0,1,0,0,1,0,0,0,1,1,1,0,1,1,0,0,
								1,0,1,1,0,1,1,1,0,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,1,0,1,1,1,0,0,1,
								0,1,0,0,1,0,0,0,1,0,1,1,0,1,1,1,1,0,1,1,0,1,1,1,0,1,0,0,0,1,1,0,
								1,0,1,1,0,1,1,1,0,0,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,1,1,0,1,1,0,0,
								1,0,1,1,0,1,1,1,0,0,0,1,1,1,0,1,0,1,0,0,1,0,0,0,1,1,1,0,0,0,1,1};


								 
static const u8 boolTable[32] = {0,0,1,1,0,0,1,0,0,1,1,0,1,1,0,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,0,0};
#endif



/* Mandatory functions */

/*
 * Key and message independent initialization. This function will be
 * called once when the program starts (e.g., to build expanded S-box
 * tables).
 */
void ECRYPT_init();

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize);                /* IV size in bits. */ 

/*
 * IV setup. After having called ECRYPT_keysetup(), the user is
 * allowed to call ECRYPT_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const u8* iv);



/*
 * Encryption/decryption of arbitrary length messages.
 *
 * For efficiency reasons, the API provides two types of
 * encrypt/decrypt functions. The ECRYPT_encrypt_bytes() function
 * (declared here) encrypts byte strings of arbitrary length, while
 * the ECRYPT_encrypt_blocks() function (defined later) only accepts
 * lengths which are multiples of ECRYPT_BLOCKLENGTH.
 * 
 * The user is allowed to make multiple calls to
 * ECRYPT_encrypt_blocks() to incrementally encrypt a long message,
 * but he is NOT allowed to make additional encryption calls once he
 * has called ECRYPT_encrypt_bytes() (unless he starts a new message
 * of course). For example, this sequence of calls is acceptable:
 *
 * ECRYPT_keysetup();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_blocks();
 *
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_bytes();
 * 
 * The following sequence is not:
 *
 * ECRYPT_keysetup();
 * ECRYPT_ivsetup();
 * ECRYPT_encrypt_blocks();
 * ECRYPT_encrypt_bytes();
 * ECRYPT_encrypt_blocks();
 */

void ECRYPT_encrypt_bytes(
  ECRYPT_ctx* ctx, 
  const u8* plaintext, 
  u8* ciphertext, 
  u32 msglen);                /* Message length in bytes. */ 

void ECRYPT_decrypt_bytes(
  ECRYPT_ctx* ctx, 
  const u8* ciphertext, 
  u8* plaintext, 
  u32 msglen);                /* Message length in bytes. */ 

//kevin edit
# define LEN 20   //20(byte)*8=160-bit 的内部状态
# define KSLen 5	// key stream lengh (byte)
# define T_NUM 50000 //每一组差分对应的测试用例的个数
//# define DIR "D:\\小琦\\Grain\\Grain_data_imp\\Grain_data_KSLen_4_L_1-4_T_Num_4096_imp_O(T)_2^36\\"
# define DIR "D:\\Grain_data_imp\\Grain_data_KSLen_2_L_1-4_T_Num_256\\"


void grain_state_load(ECRYPT_ctx* ctx, u8* state);
u32 posIdx(u32 pos);
u32 rotateIdx(u32 pos);

void inputOutputDiff(u32 L,u32 sam_N);
void inputOutputDiffForSpecificDiff(u32 L,u32 *pos);
void cal_average_OutputDiff(u32 L,u32 sam_N);

void searchAllNearColStates(u32 L);
void combination_for_search(u32 n,u32 k,u32 curr,u32 *B, u8 *diff_state);
void combination_for_search_imp(u32 n,u32 k);
bool combin_for_search_imp_sub(u32 k,u32* v);
void genOutput_diff(u8 *input_diff);
void genOutput_diff_imp(u32 k,u32 *v);
void cal_ave_rows(string dirName);
//kevin edit converter
void string2byte(u8* bArray,u32 bLen,string str);
string char2HexString(u8* bArray,u32 bLen);
string int_2_string(int a);
unsigned long long char_2_long(u8 *arr,u32 Len);
int comp(const void *a,const void *b);
int comp_struct(const void *a,const void *b);
string long_to_hexString(unsigned long long val,const u32 charLen);
bool state_comp(u8 *state,u32 state_Len,string str_state);
//kevin edit simple algorithm supporting
void combination(int n,int k,int curr,int *B);
void simple_comb(u32 n, u32 k, u32 *v);
bool simple_comb_sub(u32 k,u32 *v);
//kevin edit Cal_Average_Size_Special_tables
long long cal_table_size(string dir,string fileName);
void cal_All_files();
long long sub_routine(u32 m, u32 *v, u32 i, string dir);
bool sub_routine_enumerate(u32 m,u32 *v,int i,string dir);

void cal_special_tables_ISD_prop();
bool sub_routine_enumerate_SP(u32 m,u32 *v,int i,string dir);
void sub_routine_SP(u32 m, u32 *v, u32 i, string dir);
void cal_table_size_SP(string dir,string fileName);
/* Optional features */

/* 
 * For testing purposes it can sometimes be useful to have a function
 * which immediately generates keystream without having to provide it
 * with a zero plaintext. If your cipher cannot provide this function
 * (e.g., because it is not strictly a synchronous cipher), please
 * reset the ECRYPT_GENERATES_KEYSTREAM flag.
 */

#define ECRYPT_GENERATES_KEYSTREAM
#ifdef ECRYPT_GENERATES_KEYSTREAM

void ECRYPT_keystream_bytes(
  ECRYPT_ctx* ctx,
  u8* keystream,
  u32 length);                /* Length of keystream in bytes. */

#endif

//kevin edit, for backward keystream generate
#define ECRYPT_GENERATES_BACKWARD_KEYSTREAM
#ifdef ECRYPT_GENERATES_BACKWARD_KEYSTREAM
void ECRYPT_keystream_backward_bytes(
  ECRYPT_ctx* ctx, 
  u8* keystream, 
  u32 msglen);
#endif


//test
void enumerate_HW(int d,int len);
void combination_for_search_HM(int len,int curr_HM);
bool combination_for_search_HM_sub(int curr_HM,u32* v);