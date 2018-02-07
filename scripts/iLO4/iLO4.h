struct MOD_STATUS
{
  int dep_offset;
  BOOT_MOD *parent;
  int field_8;
  int field_C;
  int load_errno;
};

struct BOOT_MOD
{
  void *constructor;
  void *destructor;
  char *name;
  void *dependencies;
  MOD_STATUS mod_status;
};

struct __attribute__((aligned(4))) MAP_ENTRY
{
  MAP_ENTRY *next;
  const char *ptr_name;
  void *base;
  int size;
  int access;
  int field_14;
};

struct __attribute__((aligned(4))) MEMORY_REGION
{
  int id;
  int field_4;
  int low;
  int high;
  int field_10;
  int field_14;
  int field_18;
  int field_1C;
  char *mr_name;
  int field_24;
  MEMORY_REGION *next;
  MEMORY_REGION *self;
  int field_30;
};

struct MEM_INFO
{
  int id;
  int field_4;
  int low;
  int high;
  int field_10;
  int field_14;
};

struct BSS_ENTRY
{
  void *ptr;
  int init_value;
  int size;
};
