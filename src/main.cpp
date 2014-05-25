#ifdef _WIN32
	#define _CRT_SECURE_NO_WARNINGS
	#include <Windows.h>
#endif

#include <omp.h>
#include <stdio.h>
#include <vector>
#include <stdint.h>
#include <memory>

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

inline bool IsCodeChar(char ch){
	switch(ch){
	case '+':
	case '-':
	case '<':
	case '>':
	case '[':
	case ']':
	case '.':
	case ',':
		return true;

	default: return false;
	}
}

// The pointer to our memory is in ebx
// The current pointer index is in eax
// ecx is used sometimes as a temporary register
ExecutableFunc GenerateCode(const char *strUnfiltered, size_t lenUnfiltered){
	size_t i;
	size_t len = 0;

	std::unique_ptr<char[]> str(new char[lenUnfiltered]);
	{
		for(i = 0; i < lenUnfiltered; ++i){
			if(!IsCodeChar(strUnfiltered[i])) continue;
			str[len++] = strUnfiltered[i];
		}
		str[len] = 0;
	}
	

	i = 0;

	std::vector<uint8_t> code;

	std::vector<size_t> offsetsToSubtractPos;
	std::vector<size_t> openBrackets;

	// int 3
	//code.push_back(0xCC);

	// push eax
	code.push_back(0x50);

	// push ebx
	code.push_back(0x53);

	// push ecx
	code.push_back(0x51);

	// mov ebx, [ebp + 16]
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
	

	auto Matches = [&](const char *m){
		if(strncmp(m, &str[i], strlen(m)) != 0) return false;
		i += strlen(m);
		return true;
	};

	auto PeekMatches = [&](const char *m){
		return strncmp(m, &str[i], strlen(m)) != 0;
	};


	while(i < len){
		if(Matches("[-]")){
			// mov byte [ebx + eax], 0
			code.push_back(0xC6);
			code.push_back(0x04);
			code.push_back(0x03);
			code.push_back(0x00);
			continue;
		}

		if(Matches("[->+++++<]")){
			uint8_t multAmount = 5;
			uint8_t registerOffset = 1;

			// mov cl, [ebx + eax]
			code.push_back(0x8A);
			code.push_back(0x0C);
			code.push_back(0x03);

			// imul ecx, multAmount
			code.push_back(0x6B);
			code.push_back(0xC9);
			code.push_back(multAmount);

			// mov [ebx + eax + registerOffset], cl
			code.push_back(0x88);
			code.push_back(0x4C);
			code.push_back(0x03);
			code.push_back(registerOffset);

			// mov byte [ebx + eax], 0
			code.push_back(0xC6);
			code.push_back(0x04);
			code.push_back(0x03);
			code.push_back(0x00);
			continue;
		}

		if(PeekMatches("+>+>")){
			size_t count = 0;
			while(Matches("+>") && count < 8) ++count;
			if(count > 0){
				for(size_t j = 0; j < count; ++j){
					// add [eax + ebx + j], 1
					code.push_back(0x80);
					code.push_back(0x44);
					code.push_back(0x03);
					code.push_back(j);
					code.push_back(0x01);
				}

				// add eax, count
				code.push_back(0x83);
				code.push_back(0xC0);
				code.push_back(count);
			}
		}

		if(PeekMatches("->->")){
			size_t count = 0;
			while(Matches("->") && count < 8) ++count;
			if(count > 0){
				for(size_t j = 0; j < count; ++j){
					// add [eax + ebx + j], 1
					code.push_back(0x80);
					code.push_back(0x6C);
					code.push_back(0x03);
					code.push_back(j);
					code.push_back(0x01);
				}

				// add eax, count
				code.push_back(0x83);
				code.push_back(0xC0);
				code.push_back(count);
			}
		}


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

		++i;
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
	uint8_t memory[30000];
	memset(memory, 0, sizeof(memory));

	double start, end;

	if(argc < 2){
		printf("Usage: %s [filename]", argv[0]);
		return 1;
	}

	FILE *f = fopen(argv[1], "rb");

	if(f == NULL){
		puts("Couldn't find file");
		return 1;
	}

	fseek(f, 0, SEEK_END);
	
	size_t len = ftell(f);
	fseek(f, 0, SEEK_SET);

	char *code = (char*)malloc(len + 1);

	fread(code, 1, len, f);
	code[len] = 0;

	start = omp_get_wtime();
	auto func = GenerateCode(code, len);
	end = omp_get_wtime();
	printf("JIT compilation took %f ms\n", int((end - start)*1000));
	
	if(len < 1024){
		printf("%s\n", code);
	}

	puts("================");
	
	start = omp_get_wtime();
	func(memory);
	end = omp_get_wtime();

	printf("\n================\nExecution took %d ms\n", int((end - start)*1000));

	free(code);
}
