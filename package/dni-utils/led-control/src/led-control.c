
/*
 * 需要配合ledtrigger使用
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#define SYS_CLASS_LED "/sys/class/leds"

#define LED_AMBER (1 << 0)
#define LED_GREEN (1 << 1)

#define LED_OFF         0
#define LED_ON          1
#define LED_BLINK       2
#define LED_FAST_BLINK  3

struct gpio_led {
    char *name;
    unsigned color_int;
    int index;
};

enum LED_INDEX {
    LED_INDEX_PWR = 0,
    LED_INDEX_WAN1,
    LED_INDEX_CLOUD,
    LED_INDEX_VPN,
    LED_INDEX_MAX
};

static char *led_name;
static char *led_color_str;
static char *led_state_str;

static int led_color_int = 0;
static int led_state_int = LED_OFF;

static struct gpio_led *led;

struct gpio_led br500_leds[] = {
    {
        .name = "power",
        .color_int = LED_AMBER | LED_GREEN,
        .index = LED_INDEX_PWR,
    },
    {
        .name = "wan1",
        .color_int = LED_AMBER | LED_GREEN,
        .index = LED_INDEX_WAN1,        
    },
    {
        .name = "cloud",
        .color_int = LED_GREEN,
        .index = LED_INDEX_CLOUD,
    },
    {
        .name = "vpn",
        .color_int = LED_GREEN,
        .index = LED_INDEX_VPN,
    }, {
        /* terminating entry */
    }
};

int sys_exec(const char *fmt, ...)
{
    va_list args;
    char cmdbuf[512] = {0};

    va_start(args, fmt);
    vsnprintf(cmdbuf, sizeof(cmdbuf), fmt, args);
    va_end(args);
    
    return system(cmdbuf);
}

void led_trigger(char *label, char *trigger)
{
    sys_exec("echo \"%s\" > %s/%s/trigger", trigger, SYS_CLASS_LED, label);
}

void led_on(char *label)
{
    led_trigger(label, "default-on");
    sys_exec("echo \"1\" > %s/%s/brightness", SYS_CLASS_LED, label);
}

void led_off(char *label)
{
    led_trigger(label, "none");
}

void led_blink(char *label)
{
    led_trigger(label, "timer");
    sys_exec("echo \"300\" > %s/%s/delay_off", SYS_CLASS_LED, label);    
    sys_exec("echo \"300\" > %s/%s/delay_on", SYS_CLASS_LED, label);
}

void led_fast_blink(char *label)
{
    led_trigger(label, "timer");
    sys_exec("echo \"100\" > %s/%s/delay_off", SYS_CLASS_LED, label);    
    sys_exec("echo \"100\" > %s/%s/delay_on", SYS_CLASS_LED, label);        
}

void ledctrl_set(char *name, int led_color, int led_state)
{
    char *color = NULL;
    char ledctrl_name[64] = {0};
    
    switch(led_color)
    {
        case LED_AMBER:
            color = "amber";
            break;
        case LED_GREEN:
            color = "green";
            break;
        default:
            return;
    }

    snprintf(ledctrl_name, sizeof(ledctrl_name), "%s_%s", name, color);

    switch(led_state)
    {
        case LED_OFF:
            led_off(ledctrl_name);
            break;
        case LED_ON:
            led_on(ledctrl_name);
            break;
        case LED_BLINK:
            led_blink(ledctrl_name);
            break;
        case LED_FAST_BLINK:
            led_fast_blink(ledctrl_name);
            break;
        default:
            break;
    }
    
}

struct gpio_led *find_gpio_led(char *name)
{
	struct gpio_led *ret = NULL;

	for(ret = br500_leds; ret->name != NULL; ret ++) 
    {
		if (strcmp(ret->name, name) == 0)
        {      
			return ret;
        }
	}

    return NULL;
}

static int check_options()
{
    if(led_name == NULL)
    {
        fprintf(stderr, "no led name specified!\n");
        return -1;
    }

    if(led_color_str == NULL)
    {
        fprintf(stderr, "no led color specified!\n");
        return -1;
    }

    if(led_state_str == NULL)
    {
        fprintf(stderr, "no led state specified!\n");
        return -1;
    }

    led = find_gpio_led(led_name);
    if(led == NULL)
    {
        fprintf(stderr, "unkown led name!\n");
        return -1;
    }

    if(strcmp(led_color_str, "amber") == 0)
    {
        led_color_int = LED_AMBER;
    }
    else if(strcmp(led_color_str, "green") == 0)
    {
        led_color_int = LED_GREEN;
    }

    if(!(led_color_int & led->color_int))
    {
        fprintf(stderr, "unkown led color for %s led!\n", led_name);
        return -1;
    }

    if(strcmp(led_state_str, "on") == 0)
    {
        led_state_int = LED_ON;
    }
    else if(strcmp(led_state_str, "off") == 0)
    {
        led_state_int = LED_OFF;
    }
    else if(strcmp(led_state_str, "blink") == 0)
    {
        led_state_int = LED_BLINK;
    }
    else if(strcmp(led_state_str, "fast_blink") == 0)
    {
        led_state_int = LED_FAST_BLINK;
    }
    else
    {
        fprintf(stderr, "unkown led state for %s_%s!\n", led_name, led_color_str);
        return -1;        
    }

    return 0;
}


void usages()
{
    fprintf(stderr, "ledcontrol [-n name] [-c color] [-s status]\n");
    fprintf(stderr, "   -n      Valid String: power, wan1, cloud or vpn\n");
    fprintf(stderr, "   -c      Valid String: amber or green\n");    
    fprintf(stderr, "   -s      Valid String: on, off, blink or fast_blink\n");
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int opt = -1;

    while((opt = getopt(argc, argv, "n:c:s:")) != -1)
    {
        switch(opt)
        {
            case 'n':
                led_name = optarg;
                break;
            case 'c':
                led_color_str = optarg;
                break;
            case 's':
                led_state_str = optarg;
                break;
            default:
                usages();
        }
    }

    ret = check_options();
    if(ret < 0)
    {
        usages();
    }

    ledctrl_set(led_name, (~led_color_int & led->color_int), LED_OFF);
    ledctrl_set(led_name, (led_color_int & led->color_int), led_state_int);
    
    return 0;
}
