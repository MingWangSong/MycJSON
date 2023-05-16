/*
  Copyright (c) 2009-2017 Dave Gamble and cJSON contributors

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

// 防止重复项目中宏重复定义
#ifndef cJSON__h
  #define cJSON__h

  // 通知编译器，本文件是C语言写的库文件，用C语言方式链接（应对C++项目调用该库的情况）
  #ifdef __cplusplus
  extern "C"{
  #endif

  // 在windows环境下编译时，指定一个特定的调用约定
  #if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32))
    #define __WINDOWS__
  #endif
  #ifdef __WINDOWS__
    #define CJSON_CDECL __cdecl
    #define CJSON_STDCALL __stdcall

    #if !defined(CJSON_HIDE_SYMBOLS) && !defined(CJSON_IMPORT_SYMBOLS) && !defined(CJSON_EXPORT_SYMBOLS)
      #define CJSON_EXPORT_SYMBOLS
    #endif

    #if defined(CJSON_HIDE_SYMBOLS)
      #define CJSON_PUBLIC(type)   type CJSON_STDCALL
    #elif defined(CJSON_EXPORT_SYMBOLS)
      #define CJSON_PUBLIC(type)   __declspec(dllexport) type CJSON_STDCALL
    #elif defined(CJSON_IMPORT_SYMBOLS)
      #define CJSON_PUBLIC(type)   __declspec(dllimport) type CJSON_STDCALL
    #endif
  #else /* !__WINDOWS__ */
    #define CJSON_CDECL
    #define CJSON_STDCALL

    #if (defined(__GNUC__) || defined(__SUNPRO_CC) || defined (__SUNPRO_C)) && defined(CJSON_API_VISIBILITY)
      #define CJSON_PUBLIC(type)   __attribute__((visibility("default"))) type
    #else
      #define CJSON_PUBLIC(type) type
    #endif
  #endif

  // 项目版本
  #define CJSON_VERSION_MAJOR 1
  #define CJSON_VERSION_MINOR 7
  #define CJSON_VERSION_PATCH 15

  // stddef.h定义了各种变量类型和宏
  #include <stddef.h>

  // cJSON中的类型定义
  #define cJSON_Invalid (0)
  #define cJSON_False  (1 << 0)
  #define cJSON_True   (1 << 1)
  #define cJSON_NULL   (1 << 2)
  #define cJSON_Number (1 << 3)
  #define cJSON_String (1 << 4)
  #define cJSON_Array  (1 << 5)
  #define cJSON_Object (1 << 6)
  #define cJSON_Raw    (1 << 7)
  #define cJSON_IsReference (1 << 8)
  #define cJSON_StringIsConst (1 << 9)

  // cJSON结构体
  typedef struct cJSON
  {
      // next/prev指针用来遍历数组/对象链表，或者通过函数GetArraySize/GetArrayItem/GetObjectItem使用
      struct cJSON *next;
      struct cJSON *prev;
      // 数组或对象类型节点将有一个指向数组/对象链表的子指针
      struct cJSON *child;
      // 标注cJSON节点类型
      int type;
      // cJSON节点 value值（写入valueint已弃用，请改用cJSON_SetNumberValue）
      char *valuestring;
      int valueint;
      double valuedouble;
      //cJSON节点 key值
      char *string;
  } cJSON;

  // malloc/free钩子结构体，malloc/free在Windows上都是CDECL
  typedef struct cJSON_Hooks
  {
      void *(CJSON_CDECL *malloc_fn)(size_t sz);
      void (CJSON_CDECL *free_fn)(void *ptr);
  } cJSON_Hooks;

  typedef int cJSON_bool;

  // cJSON这是为了防止堆栈溢出，限制嵌套数组/对象的深度
  #ifndef CJSON_NESTING_LIMIT
    #define CJSON_NESTING_LIMIT 1000
  #endif

  // 返回字符串形式的cJSON版本
  CJSON_PUBLIC(const char*) cJSON_Version(void);

  // 为cJSON提供malloc, realloc和free函数
  CJSON_PUBLIC(void) cJSON_InitHooks(cJSON_Hooks* hooks);
  // 使用cjson_initooks设置的malloc/free函数调用malloc/free对象
  CJSON_PUBLIC(void *) cJSON_malloc(size_t size);
  CJSON_PUBLIC(void) cJSON_free(void *object);

  // 解析JSON字符串
  CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value);
  CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length);
  // ParseWithOpts允许您要求(并检查)JSON是否为空终止，并检索指向已解析的最终字节的指针。
  // 如果在return_parse_end中提供ptr并且解析失败，则return_parse_end将包含指向错误的指针，因此将匹配cJSON_GetErrorPtr()。
  CJSON_PUBLIC(cJSON *) cJSON_ParseWithOpts(const char *value, const char **return_parse_end, cJSON_bool require_null_terminated);
  CJSON_PUBLIC(cJSON *) cJSON_ParseWithLengthOpts(const char *value, size_t buffer_length, const char **return_parse_end, cJSON_bool require_null_terminated);

  // 序列化cJSON节点
  CJSON_PUBLIC(char *) cJSON_Print(const cJSON *item);
  // 将cJSON节点序列化为文本以进行传输/存储，而不需要任何格式化
  CJSON_PUBLIC(char *) cJSON_PrintUnformatted(const cJSON *item);
  // 使用缓冲策略序列化cJSON节点；可通过prebuffer设置初始缓冲区大小，以便减少空间分配次数；fmt =0表示未格式化，=1表示已格式化
  CJSON_PUBLIC(char *) cJSON_PrintBuffered(const cJSON *item, int prebuffer, cJSON_bool fmt);
  // 使用给定长度的内存中已分配的缓冲区来序列化cJSON节点。成功时返回1，失败时返回0。
  // 注意:cJSON在估计它将使用多少内存时并不总是100%准确，所以为了安全起见，分配比实际需要多5字节的内存
  CJSON_PUBLIC(cJSON_bool) cJSON_PrintPreallocated(cJSON *item, char *buffer, const int length, const cJSON_bool format);

  // 删除cJSON节点和所有子节点
  CJSON_PUBLIC(void) cJSON_Delete(cJSON *item);

  // 返回child下有多个节点（数组或对象）
  CJSON_PUBLIC(int) cJSON_GetArraySize(const cJSON *array);
  // 从子节点child中检索编号为“index”的节点，如果不成功则返回NULL。
  CJSON_PUBLIC(cJSON *) cJSON_GetArrayItem(const cJSON *array, int index);
  // 根据key查找子节点child，不区分大小写。
  CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string);
  // 根据key查找子节点child，区分大小写。
  CJSON_PUBLIC(cJSON *) cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string);
  // 根据key查找子节点child是否存在该key节点，不区分大小写。
  CJSON_PUBLIC(cJSON_bool) cJSON_HasObjectItem(const cJSON *object, const char *string);

  // 用于解析报错信息，这将返回指向解析错误的指针。
  CJSON_PUBLIC(const char *) cJSON_GetErrorPtr(void);

  // 检查项目类型并返回节点对应的值
  CJSON_PUBLIC(char *) cJSON_GetStringValue(const cJSON * const item);
  CJSON_PUBLIC(double) cJSON_GetNumberValue(const cJSON * const item);

  // 检查cJOSN节点的类型
  CJSON_PUBLIC(cJSON_bool) cJSON_IsInvalid(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsFalse(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsTrue(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsBool(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsNull(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsNumber(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsString(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsArray(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsObject(const cJSON * const item);
  CJSON_PUBLIC(cJSON_bool) cJSON_IsRaw(const cJSON * const item);

  // 创建不同类型cJSON节点
  CJSON_PUBLIC(cJSON *) cJSON_CreateNull(void);
  CJSON_PUBLIC(cJSON *) cJSON_CreateTrue(void);
  CJSON_PUBLIC(cJSON *) cJSON_CreateFalse(void);
  CJSON_PUBLIC(cJSON *) cJSON_CreateBool(cJSON_bool boolean);
  CJSON_PUBLIC(cJSON *) cJSON_CreateNumber(double num);
  CJSON_PUBLIC(cJSON *) cJSON_CreateString(const char *string);
  CJSON_PUBLIC(cJSON *) cJSON_CreateRaw(const char *raw);
  CJSON_PUBLIC(cJSON *) cJSON_CreateArray(void);
  CJSON_PUBLIC(cJSON *) cJSON_CreateObject(void);
  // 创建一个字符串，其中valuestring为引用字符串，它不会被cJSON_Delete释放
  CJSON_PUBLIC(cJSON *) cJSON_CreateStringReference(const char *string);
  // 创建一个对象/数组，只引用它的元素 它们不会被cJSON_Delete释放
  CJSON_PUBLIC(cJSON *) cJSON_CreateObjectReference(const cJSON *child);
  CJSON_PUBLIC(cJSON *) cJSON_CreateArrayReference(const cJSON *child);
  // 创建指定大小的数组（不同类型），参数count不能大于number数组中的元素个数，否则数组访问将越界
  CJSON_PUBLIC(cJSON *) cJSON_CreateIntArray(const int *numbers, int count);
  CJSON_PUBLIC(cJSON *) cJSON_CreateFloatArray(const float *numbers, int count);
  CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count);
  CJSON_PUBLIC(cJSON *) cJSON_CreateStringArray(const char *const *strings, int count);

  // 在child指针下添加数组/对象
  CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToArray(cJSON *array, cJSON *item);
  CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);
  // 当string绝对是const时使用此方法，并且一定会在cJSON对象中存活，该函数在设置key之前，会确保item->type & cJSON_StringIsConst == 0
  CJSON_PUBLIC(cJSON_bool) cJSON_AddItemToObjectCS(cJSON *object, const char *string, cJSON *item);
  // 将对cJSON节点的引用追加到指定的数组/对象，当想要将现有的cJSON节点添加到新的cJSON节点中，但又不想破坏现有的cJSON时，请使用此方法。
  CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToArray(cJSON *array, cJSON *item);
  CJSON_PUBLIC(cJSON_bool) cJSON_AddItemReferenceToObject(cJSON *object, const char *string, cJSON *item);

  // 从父节点中移除/分离child中的结点。
  CJSON_PUBLIC(cJSON *) cJSON_DetachItemViaPointer(cJSON *parent, cJSON * const item);
  CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromArray(cJSON *array, int which);
  CJSON_PUBLIC(void) cJSON_DeleteItemFromArray(cJSON *array, int which);
  CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObject(cJSON *object, const char *string);
  CJSON_PUBLIC(cJSON *) cJSON_DetachItemFromObjectCaseSensitive(cJSON *object, const char *string);
  CJSON_PUBLIC(void) cJSON_DeleteItemFromObject(cJSON *object, const char *string);
  CJSON_PUBLIC(void) cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string);

  // 更新节点。其中，插入新节点时，将插入点以后的节点向右挪一个位置
  CJSON_PUBLIC(cJSON_bool) cJSON_InsertItemInArray(cJSON *array, int which, cJSON *newitem);
  CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemViaPointer(cJSON * const parent, cJSON * const item, cJSON * replacement);
  CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInArray(cJSON *array, int which, cJSON *newitem);
  CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObject(cJSON *object,const char *string,cJSON *newitem);
  CJSON_PUBLIC(cJSON_bool) cJSON_ReplaceItemInObjectCaseSensitive(cJSON *object,const char *string,cJSON *newitem);

  // 复制cJSON节点，浅copy和深copy recurse==true:深
  CJSON_PUBLIC(cJSON *) cJSON_Duplicate(const cJSON *item, cJSON_bool recurse);

  // 递归比较两个cJSON项是否相等。如果a或b为NULL或无效，它们将被认为是不相等的。 Case_sensitive决定对象键是区分大小写(1)还是不区分大小写(0)
  CJSON_PUBLIC(cJSON_bool) cJSON_Compare(const cJSON * const a, const cJSON * const b, const cJSON_bool case_sensitive);

  // 简化JSON字符串，从字符串中删除空白字符(如' '，'\t'，'\r'，'\n')，输入指针json不能指向只读地址区域，比如字符串常量。
  CJSON_PUBLIC(void) cJSON_Minify(char *json);

  // 用于创建cJSON节点并添加至指定节点，成功则返回新添加的cJSON节点，失败时返回NULL。
  CJSON_PUBLIC(cJSON*) cJSON_AddNullToObject(cJSON * const object, const char * const name);
  CJSON_PUBLIC(cJSON*) cJSON_AddTrueToObject(cJSON * const object, const char * const name);
  CJSON_PUBLIC(cJSON*) cJSON_AddFalseToObject(cJSON * const object, const char * const name);
  CJSON_PUBLIC(cJSON*) cJSON_AddBoolToObject(cJSON * const object, const char * const name, const cJSON_bool boolean);
  CJSON_PUBLIC(cJSON*) cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number);
  CJSON_PUBLIC(cJSON*) cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string);
  CJSON_PUBLIC(cJSON*) cJSON_AddRawToObject(cJSON * const object, const char * const name, const char * const raw);
  CJSON_PUBLIC(cJSON*) cJSON_AddObjectToObject(cJSON * const object, const char * const name);
  CJSON_PUBLIC(cJSON*) cJSON_AddArrayToObject(cJSON * const object, const char * const name);

  // 由于valueint被弃用，当分配数值给valueint时，也需要将其传播给valuedouble。
  #define cJSON_SetIntValue(object, number) ((object) ? (object)->valueint = (object)->valuedouble = (number) : (number))
  // 新的设置number的函数，作者表示：don't ask me
  CJSON_PUBLIC(double) cJSON_SetNumberHelper(cJSON *object, double number);
  #define cJSON_SetNumberValue(object, number) ((object != NULL) ? cJSON_SetNumberHelper(object, (double)number) : (number))
  // 修改cJSON_String对象的valuestring值，仅当对象类型为cJSON_String时生效
  CJSON_PUBLIC(char*) cJSON_SetValuestring(cJSON *object, const char *valuestring);

  // 如果对象不是布尔类型，则不执行任何操作并返回cJSON_Invalid，否则返回新类型
  #define cJSON_SetBoolValue(object, boolValue) ( \
      (object != NULL && ((object)->type & (cJSON_False|cJSON_True))) ? \
      (object)->type=((object)->type &(~(cJSON_False|cJSON_True)))|((boolValue)?cJSON_True:cJSON_False) : \
      cJSON_Invalid\
  )

  // 用于在数组或对象上遍历
  #define cJSON_ArrayForEach(element, array) for(element = (array != NULL) ? (array)->child : NULL; element != NULL; element = element->next)

  #ifdef __cplusplus
  }
  #endif
#endif
