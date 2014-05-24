
#ifdef _WIN32
	#define _CRT_SECURE_NO_WARNINGS
	#include <Windows.h>
#endif

#include <stdio.h>
#include <vector>
#include <stdint.h>

typedef void (*ExecutableFunc)(uint8_t *memory);


#ifdef _WIN32
void PutCharWrapper(int ch){
	if(ch == '\n'){
		putchar('\r');
		putchar('\n');
	}else{
		putchar(ch);
	}
}
#endif

// The pointer to our memory is in ebx
// The current pointer index is in eax
// ecx is used sometimes as a temporary register
ExecutableFunc GenerateCode(const char *str, size_t len){
	std::vector<uint8_t> code;

	std::vector<size_t> offsetsToSubtractPos;
	std::vector<size_t> openBrackets;

	// int 3
	code.push_back(0xCC);

	// push eax
	code.push_back(0x50);

	// push ebx
	code.push_back(0x53);

	// push ecx
	code.push_back(0x51);

	// mov ebx, [ebp + 12]
	code.push_back(0x8B);
	code.push_back(0x5C);
	code.push_back(0x24);
	code.push_back(0x10);

	// mov eax, 0
	code.push_back(0xB8);
	code.push_back(0x00);
	code.push_back(0x00);
	code.push_back(0x00);
	code.push_back(0x00);

	for(size_t i = 0; i < len; ++i){
		switch(str[i]){
			case '+': {
				uint8_t count = 1;

				while(count < 127 && i + 1 < len && str[i + 1] == '+'){
					++i;
					++count;
				}

				// add byte [ebx + eax], count
				code.push_back(0x80);
				code.push_back(0x04);
				code.push_back(0x03);
				code.push_back(count);
			}; break;

			case '-': {
				uint8_t count = 1;

				while(count < 127 && i + 1 < len && str[i + 1] == '-'){
					++i;
					++count;
				}

				// sub byte [ebx + eax], count
				code.push_back(0x80);
				code.push_back(0x2C);
				code.push_back(0x03);
				code.push_back(count);

			}; break;

			case '<': {
				uint8_t count = 1;

				while(count < 127 && i + 1 < len && str[i + 1] == '<'){
					++i;
					++count;
				}

				
				// sub eax, count
				code.push_back(0x83);
				code.push_back(0xE8);
				code.push_back(count);
			}; break;

			case '>': {
				uint8_t count = 1;

				while(count < 127 && i + 1 < len && str[i + 1] == '>'){
					++i;
					++count;
				}
				
				// add eax, count
				code.push_back(0x83);
				code.push_back(0xC0);
				code.push_back(count);
			}; break;

			case '.': {
				// movzx ecx, byte [ebx + eax]
				code.push_back(0x0F);
				code.push_back(0xB6);
				code.push_back(0x0C);
				code.push_back(0x03);
				
				// push eax
				code.push_back(0x50);

				// push ebx
				code.push_back(0x53);

				// push ecx
				code.push_back(0x51);

				// call absolute
				code.push_back(0xE8);

#ifdef _WIN32
				uintptr_t ptr = (uintptr_t) &PutCharWrapper - 4;
#else
				uintptr_t ptr = (uintptr_t) &putchar - 4;
#endif
				
				offsetsToSubtractPos.push_back(code.size());
				code.push_back((ptr >>  0) & 0xFF);
				code.push_back((ptr >>  8) & 0xFF);
				code.push_back((ptr >> 16) & 0xFF);
				code.push_back((ptr >> 24) & 0xFF);

				// add esp, 4
				code.push_back(0x83);
				code.push_back(0xC4);
				code.push_back(0x04);

				// pop ebx
				code.push_back(0x5B);

				// pop eax
				code.push_back(0x58);
			}; break;

				
			case ',': {
				// push eax
				code.push_back(0x50);

				// push ebx
				code.push_back(0x53);

				// call getchar
				code.push_back(0xE8);
				uintptr_t ptr = (uintptr_t) &getchar - 4;
				
				offsetsToSubtractPos.push_back(code.size());
				code.push_back((ptr >>  0) & 0xFF);
				code.push_back((ptr >>  8) & 0xFF);
				code.push_back((ptr >> 16) & 0xFF);
				code.push_back((ptr >> 24) & 0xFF);

				// mov ecx, eax
				code.push_back(0x89);
				code.push_back(0xC1);

				// pop ebx
				code.push_back(0x5B);

				// pop eax
				code.push_back(0x58);

				// mov byte[ebx + eax], cl
				code.push_back(0x88);
				code.push_back(0x0C);
				code.push_back(0x03);
			}; break;

			case '[':
				// jmp 0 (to be patched by ']')
				code.push_back(0xE9);
				code.push_back(0x00);
				code.push_back(0x00);
				code.push_back(0x00);
				code.push_back(0x00);
				openBrackets.push_back(code.size());
			break;
			

			case ']': {
				if(openBrackets.empty()){
					// Mismatched brackets
					return NULL;
				}

				// Patch the '[' to jump inconditionally to here
				{
					int32_t off = code.size() - openBrackets.back();

					uint8_t *data = &code.data()[openBrackets.back() - 4];
					data[0] = (off >>  0) & 0xFF;
					data[1] = (off >>  8) & 0xFF;
					data[2] = (off >> 16) & 0xFF;
					data[3] = (off >> 24) & 0xFF;
				}

				// mov cl, byte [eax + ebx]
				code.push_back(0x8A);
				code.push_back(0x0C);
				code.push_back(0x18);

				// cmp cl, 0
				code.push_back(0x80);
				code.push_back(0xF9);
				code.push_back(0x00);

				// jne, rel32
				code.push_back(0x0F);
				code.push_back(0x85);
				
				union {
					int32_t s;
					uint32_t u;
				} jump;

				jump.s = openBrackets.back() - code.size() - 4;
				openBrackets.pop_back();

				code.push_back((jump.u >>  0) & 0xFF);
				code.push_back((jump.u >>  8) & 0xFF);
				code.push_back((jump.u >> 16) & 0xFF);
				code.push_back((jump.u >> 24) & 0xFF);
			}; break;
		}
	}

	if(!openBrackets.empty()){
		// Mismatched brackets
		return NULL;
	}

	// pop ecx
	code.push_back(0x59);

	// pop ebx
	code.push_back(0x5B);

	// pop eax
	code.push_back(0x58);

	// ret
	code.push_back(0xC3);

	uint8_t *func;

#ifdef _WIN32
	func = (uint8_t*) VirtualAlloc(NULL, code.size(), MEM_COMMIT, PAGE_READWRITE);
#else
	func = (uint8_t*) mmap(NULL, code.size(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if(func == MAP_FAILED) return NULL;
#endif


	memcpy(func, code.data(), code.size());
	
	for(size_t off : offsetsToSubtractPos){
		*(uintptr_t*)&func[off] -= (uintptr_t) &func[off];
	}
	
	if(1){
		FILE *f = fopen("jit.out", "wb+");
		fwrite(func, 1, code.size(), f);
		fclose(f);
	}

#ifdef _WIN32
	DWORD oldProtect;
	VirtualProtect(func, code.size(), PAGE_EXECUTE_READ, &oldProtect);
#else
	mprotect(func, code.size(), PROT_EXEC | PROT_READ);
#endif

	printf("Code generated has %d bytes\n", code.size());
	return (ExecutableFunc) func;
}

int main(int argc, const char *argv[]){
	uint8_t memory[2048];
	memset(memory, 0, sizeof(memory));


	if(argc < 2){
		printf("Usage: %s filename", argv[0]);
		return 1;
	}

	FILE *f = fopen(argv[1], "rb");
	fseek(f, 0, SEEK_END);
	
	size_t len = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *code = (char*)malloc(len + 1);

	fread(code, 1, len, f);
	code[len] = 0;

	auto func = GenerateCode(code, len);
	printf("EXECUTING\n");
	
	if(len < 1024){
		printf("%s\n================\n", code);
	}

	func(memory);
	printf("\n================\nEXECUTION ENDED\n");

	free(code);
}