#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/prompt.h"

/* Custom validator example */
bool validate_project_name(const char *input, char *error_msg, size_t error_size) {
    if (strlen(input) < 3) {
        snprintf(error_msg, error_size, "Project name must be at least 3 characters");
        return false;
    }
    
    /* Check for valid characters (alphanumeric, dash, underscore) */
    for (size_t i = 0; i < strlen(input); i++) {
        char c = input[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            snprintf(error_msg, error_size, "Use only letters, numbers, dash, and underscore");
            return false;
        }
    }
    
    return true;
}

/* Custom validator wrapper for minimum password length */
bool validate_password(const char *input, char *error_msg, size_t error_size) {
    if (strlen(input) < 8) {
        snprintf(error_msg, error_size, "Password must be at least 8 characters");
        return false;
    }
    return true;
}

int main(void) {
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║   CLI Prompt Library Demo              ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n");
    
    /* Initialize the prompt library */
    // prompt_init();
    
    /* 1. Text Input with validation */
    struct input_config project_config = {
        .title = "Project name:",
        .placeholder = "my-awesome-project",
        .validator = validate_project_name,
        .max_length = 100,
        .required = true
    };
    
    char *project_name = prompt_input(&project_config);
    printf("\n");
    
    /* 2. Single Select */
    const char *frameworks[] = {
        "Vanilla",
        "Vue",
        "React",
        "Preact",
        "Lit",
        "Svelte",
        "Solid",
        "Qwik",
        "Angular",
        "Marko",
        "Others"
    };
    
    struct select_config framework_config = {
        .title = "Select a framework:",
        .options = frameworks,
        .option_count = sizeof(frameworks) / sizeof(frameworks[0]),
        .default_index = 4  /* Lit is default */
    };
    
    int framework_idx = prompt_select(&framework_config);
    printf("\n");
    
    /* 4. Email input with validation */
    struct input_config email_config = {
        .title = "Email address:",
        .placeholder = "user@example.com",
        .validator = NULL,
        .max_length = 100,
        .required = false
    };
    
    char *email = prompt_input(&email_config);
    printf("\n");
    
    /* 6. Confirmation */
    struct confirm_config install_config = {
        .title = "Install dependencies with npm and start now?",
        .is_yes_default = true
    };
    
    bool should_install = prompt_confirm(&install_config);
    printf("\n");
    
    /* Display summary */
    printf("╔════════════════════════════════════════╗\n");
    printf("║   Configuration Summary                ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n");
    printf("Project Name:  %s\n", project_name);
    printf("Framework:     %s\n", frameworks[framework_idx]);
    printf("Email:         %s\n", strlen(email) > 0 ? email : "(not provided)");
    printf("Password:      %s\n", "********");
    printf("Install:       %s\n", should_install ? "Yes" : "No");
    printf("\n");
    
    if (should_install) {
        printf("✓ Starting installation...\n");
    } else {
        printf("✓ Configuration saved. Run 'npm install' manually.\n");
    }
    
    /* Cleanup */
    prompt_cleanup();
    free(project_name);
    free(email);
    
    return 0;
}