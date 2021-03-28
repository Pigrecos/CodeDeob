//Display flags
{$DEFINE INFO} 
{$UNDEF SHOW_NOP}
{$DEFINE SHOW_ADDR}
//{$DEFINE TESTING}
{$DEFINE ENABLE_TEST_FUNCTIONS}
{$DEFINE  USE_ANONYMOUS_METHODS}

 {$POINTERMATH ON}

//Emulation testing values
Const TEXT_ADDRESS = $501000;
const STACK_ADDRESS= $1000;
Const EMU_SIZE     = 2 * 1024 * 1024;

//Optimizations flags
{$DEFINE NO_NOP}
{$DEFINE FIRST_PASS}
{$DEFINE SEQUENTIAL_SEARCH}

//junk elimination
{$DEFINE REMOVE_FLAG_INS}
{$UNDEF  REMOVE_UNUSED}

//Stack expansion
const STACK_DISPLACEMENT = $400

{$WARN IMPLICIT_STRING_CAST OFF}
{$WARN IMPLICIT_STRING_CAST_LOSS OFF}

//Registers structure
//{$DEFINE REGISTERS_SIZE sizeof(Registers)/sizeof(uint64_t)