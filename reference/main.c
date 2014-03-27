#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "pufferfish.h"
#include "pfcrypt.h"

int main (int argc, char **argv)
{
	unsigned int t_cost = 0, m_cost = 0, saltlen = 16;
	char *tmp, *settings, *hash, *salt = NULL;
	char password[255];


	if (argc < 3)
	{
		fprintf (stderr, "Usage: %s [t_cost] [m_cost] <salt> \n", argv[0]);
		return 1;
	}

	while (1)
	{
		tmp = getpass ("Password: ");
		memmove (password, tmp, strlen(tmp));
		tmp = getpass ("Re-enter password: ");

		if ((strlen (password) == strlen (tmp)) && (! strncmp (password, tmp, strlen (password))))
			break;

		fprintf (stderr, "Passwords do not match.\n\n");
		sleep (1);
	}

	t_cost = atoi (argv[1]);
	m_cost = atoi (argv[2]);

	if (argc == 4)
	{
		salt = argv[3];
		saltlen = strlen (argv[3]);
	}

        settings = pf_gensalt ((const unsigned char *) salt, saltlen, t_cost, m_cost);
        hash = (char *) pfcrypt (password, strlen (password), settings, 32, false);
        free (settings);

        printf ("\n%s\n\n", hash);

	return 0;
}
