/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
              U T I L I T Y  F U N C T I O N  P R O T O T Y P E S 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define WORKING_DIR "/usr/local/bin/sts-2.1.2"

int		displayGeneratorOptions();
int		generatorOptions(char** streamFile);
void	chooseTests(char * statiscal_test_options);
void	fixParameters();
void	fileBasedBitStreams(char *streamFile, int mode);
void	readBinaryDigitsInASCIIFormat(FILE *fp, char *streamFile);
void	readHexDigitsInBinaryFormat(FILE *fp);
int		convertToBits(BYTE *x, int xBitLength, int bitsNeeded, int *num_0s, int *num_1s, int *bitsRead);
void	openOutputStreams(int option, int number_of_bit_stream);
void	invokeTestSuite(int option, char *streamFile, int input_file_format);
void	nist_test_suite();
