#pragma once

#define SUCCESS(format, ...) DbgPrint("[~] blister: " format, __VA_ARGS__)
#define ERROR(format, ...) DbgPrint("[!] blister: " format, __VA_ARGS__)
#define WARN(format, ...) DbgPrint("[WARNING] blister: " format, __VA_ARGS__)
#define INFO(format, ...) DbgPrint("[INFO] blister: " format, __VA_ARGS__)

#define NUMBEROFELEMENTS(element) (sizeof(element) / sizeof((element)[0]))