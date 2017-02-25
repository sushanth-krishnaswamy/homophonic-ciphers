
#include<iostream>
#include<map>
#include<vector>
#include<sstream>
#include<fstream>
#include<time.h>

using namespace std;

#define KEYS 103

struct Encryption_map{
	bool abort;
	map<char, int> char_freq;
	vector<string> words;
	vector<vector<int> > cipher_num;
	char replaced[KEYS];
	vector<int> used_keys;
};

class DictionaryProcess{

	vector<string> wordlist;
	map<int, vector<string> > dictionary_length_map;

	public:
	DictionaryProcess(string file_name){

		map_length_to_wordlist(file_name);

	}
	/*
	 * This map contains an integer column of size which maps
	 * to the list of all the words of that size
	 */
	void map_length_to_wordlist(string file_name){

		ifstream input(file_name.c_str());
		string word;
		while(getline(input, word)){
			this->wordlist.push_back(word);
		}
		input.close();
		for(unsigned int i=0; i<this->wordlist.size(); i++){
					this->dictionary_length_map[this->wordlist[i].size()].push_back(this->wordlist[i]);
				}
	}

/* This method returns
 * all the words from the dictionary with the length same as the
 * length of the least frequency word in the cipher-text*/

	vector<string> extract_words_from_dict(int word_length){
		return this->dictionary_length_map[word_length];
	}
/*
 * This method parallelly checks for the
 * length of the word with the least frequency of occurence
 * in both ciphertext list and dictionary word length list.
 * */
	int return_length_least_freq_word(vector<int> cipher_length_list){
		unsigned int num_words = this->dictionary_length_map[cipher_length_list[0]].size();
		int length = cipher_length_list[0];
		for(unsigned int i=1;i<cipher_length_list.size();i++){
			if(num_words>this->dictionary_length_map[cipher_length_list[i]].size()){
				num_words = this->dictionary_length_map[cipher_length_list[i]].size();
				length = cipher_length_list[i];
			}
		}
		return length;
	}


	bool check_pattern(string dic_word, string word){
		for(unsigned int i=0;i<word.size();i++){
			if(word[i] == '-')
				continue;
			else{
				if(word[i] != dic_word[i])
					return false;
			}
		}
		return true;
	}

	vector<string> return_pattern(string word){
		vector<string> matches = this->extract_words_from_dict(word.size());
		unsigned int i=0;
		while(i<matches.size()){
			if(!check_pattern(matches[i], word)){
				matches.erase(matches.begin() + i);
			}
			else
				i++;
		}
		return matches;
	}
};




// This is the class where the actual cryptanalysis happens.
class CryptProcess{

	string cipher;
	vector<string> words;
	vector< vector<int> > cipher_num;
	vector<int> words_length_list;
	string plain_text;
	DictionaryProcess *d;
	map<char, int> key_map;
	vector<int> used_keys;
	Encryption_map enmap;
	float total_time;
	clock_t begin_time;

	public:

	CryptProcess(string cipher, string file_name){

		this->cipher = cipher;
		this->d = new DictionaryProcess(file_name);
		this->cipher_process();
		this->create_empty_key_table();

	}

	~CryptProcess(){
		delete(d);
	}

	void create_empty_key_table(){

		map<char, int> key_map;

		key_map['a'] = 8;
		key_map['b'] = 1;
		key_map['c'] = 3;
		key_map['d'] = 4;
		key_map['e'] = 13;
		key_map['f'] = 2;
		key_map['g'] = 2;
		key_map['h'] = 6;
		key_map['i'] = 7;
		key_map['j'] = 1;
		key_map['k'] = 1;
		key_map['l'] = 4;
		key_map['m'] = 2;
		key_map['n'] = 7;
		key_map['o'] = 8;
		key_map['p'] = 2;
		key_map['q'] = 1;
		key_map['r'] = 6;
		key_map['s'] = 6;
		key_map['t'] = 9;
		key_map['u'] = 3;
		key_map['v'] = 1;
		key_map['w'] = 2;
		key_map['x'] = 1;
		key_map['y'] = 2;
		key_map['z'] = 1;

		for(int i=0;i<KEYS;i++){

			this->enmap.replaced[i] = '-';
		}
		this->enmap.char_freq = key_map;
		this->enmap.words = this->words;
		this->enmap.cipher_num = this->cipher_num;
		this->enmap.abort = false;
	}

/*
 * This method processes the cipher-text input
 * and counts the number of letters in each word of the cipher-text.
 *  */

	void cipher_process(){
		string s;
		int ctr=0;
		vector<int> c_num;
		for(unsigned int i=0;i<this->cipher.size();i++){
			if(this->cipher[i] == ' '){

				this->words.push_back(s);
				this->words_length_list.push_back(ctr);
				this->cipher_num.push_back(c_num);
				c_num.clear();
				s.clear();
				ctr=0;

			}
			else if(this->cipher[i] == ',')
				continue;
			else{
				int digit, num=0;
				while(this->cipher[i]<='9' && this->cipher[i]>='0'){
					digit = this->cipher[i] - '0'; // Type-casting is done here.
					num = num*10 + digit;
					i++;
				}
				s.push_back('-');
				ctr++;
				c_num.push_back(num);
				i--;
			}
		}

		// This appends the last word after encountering the last comma
		this->words.push_back(s);
		this->words_length_list.push_back(ctr);
		this->cipher_num.push_back(c_num);
		s.clear();
		ctr=0;
	}

	void decryption(){
			this->begin_time = clock();

			int length_least_freq_word = this->d->return_length_least_freq_word(this->words_length_list);
			vector<string> dictionary_words = this->d->extract_words_from_dict(length_least_freq_word);

			for(unsigned int i=0;i<dictionary_words.size();i++){
				string first_word = dictionary_words[i];
				Encryption_map temp_map = this->enmap;
				temp_map = begin_key_allocation(first_word, temp_map);
				if(temp_map.abort)
					continue;

				if(this->is_enmap_complete(temp_map.words)){

					this->output_plaintext(temp_map.words, temp_map.cipher_num);
					continue;
				}
	// Now call the recursive function to repeatedly check for matches.
				recursive_check(temp_map);
			}
			cout<<endl<<"Total time taken for decryption is : "<<this->total_time<<" seconds"<<endl;
		}

	Encryption_map begin_key_allocation(string first_word, Encryption_map temp_map){


		for(unsigned int i=0;i<temp_map.words.size();i++){
			if(temp_map.words[i].size() == first_word.size()){
				temp_map = update_encryption_map(temp_map, first_word, i);
				temp_map.words[i] = first_word;
				vector<int> keys = temp_map.cipher_num[i];

				for(unsigned int j=0;j<temp_map.words[i].size();j++){
					temp_map = replace_char(keys[j], temp_map.words[i][j], temp_map);
				}
				break;
			}
		}

		return temp_map;
	}

/*This method checks for already used keys and
 *exhausted character frequency before updating the map*/

	Encryption_map update_encryption_map(Encryption_map temp_map, string word, int index){

		string next_word = temp_map.words[index];
		vector<int> next_keys = temp_map.cipher_num[index];

		// key already used
		for(unsigned int i=0;i<next_keys.size();i++){
			if(next_word[i] != '-'){
		// key already replaced, do nothing
				continue;
			}
			else if(temp_map.replaced[next_keys[i]] != '-'){

				// key already used earlier in the same word
				bool abort = true;
				for(unsigned int j=0;j<i;j++){
					if(next_keys[i] == next_keys[j])
						abort = false;
				}
				if(abort){
					// Key already used, abort
					temp_map.abort = true;
					return temp_map;
				}
			}
			else if(temp_map.char_freq[word[i]] == 0){
				// Character frequency over, abort
				temp_map.abort = true;
				return temp_map;
			}
			else{

				temp_map.replaced[next_keys[i]] = word[i];
				temp_map.char_freq[word[i]]--;
			}
		}

		return temp_map;
	}

	Encryption_map replace_char(int key, char c, Encryption_map temp_map){

		for(unsigned int i=0;i<temp_map.cipher_num.size();i++){
			vector<int> keys = temp_map.cipher_num[i];
			string s = temp_map.words[i];
			for(unsigned int j=0;j<keys.size();j++){
				if(keys[j] == key){
					s[j] = c;
				}
			}
			temp_map.words[i] = s;
		}

		return temp_map;
	}

	Encryption_map replace_word(string word, Encryption_map temp_map, int index){
		temp_map.words[index] = word;
		for(unsigned int i=0;i<temp_map.words[index].size();i++){
			temp_map = replace_char(temp_map.cipher_num[index][i], temp_map.words[index][i], temp_map);
		}

		return temp_map;
	}



	int return_pos_word(vector<string> temp_words){
		int index = 0;
		int max = -1;
		for(unsigned int i=0;i<temp_words.size();i++){
			string s = temp_words[i];
			int filled = 0;
			for(unsigned int j=0;j<s.size();j++){
				if(s[j] != '-')
					filled++;
			}
			if(filled != s.size() && filled>max){
				max = filled;
				index = i;
			}
		}
		return index;
	}

	void recursive_check(Encryption_map temp_map){

		int index = return_pos_word(temp_map.words);
		// recursively check for all words of same length from the dictionary.
		vector<string> matching_words = this->d->return_pattern(temp_map.words[index]);

		if(matching_words.size() == 0){
			return;
		}

		for(unsigned int i=0;i<matching_words.size();i++){

			Encryption_map cipher_scheme = temp_map;
			cipher_scheme = update_encryption_map(cipher_scheme, matching_words[i], index);
			if(cipher_scheme.abort)
				continue;
			cipher_scheme = replace_word(matching_words[i], cipher_scheme, index);

			if(this->is_enmap_complete(cipher_scheme.words)){

				this->total_time = float(clock() - this->begin_time)/CLOCKS_PER_SEC;


				this->output_plaintext(cipher_scheme.words, cipher_scheme.cipher_num);

			}
			else{

				recursive_check(cipher_scheme);
			}
		}
	}

// This method performs the decryption of the cipher-text

	void output_plaintext(vector<string> words, vector< vector<int> >cipher_num){
		cout<<endl<<endl;
		cout<<"Our plaintext guess is : "<<endl<<endl;
		for(unsigned int i=0;i<words.size();i++){
			cout<<words[i]<<" ";
		}
		cout<<endl<<endl;

	}

/*check if encryption map is all filled out*/

	bool is_enmap_complete(vector<string> words){
		for(unsigned int i=0;i<words.size();i++){
			for(unsigned int j=0;j<words[i].size();j++){
				if(words[i][j] == '-')
					return false;
			}
		}
		return true;
	}


};

int main(){

	string cipher_text;
    string file_name = "plaintext_dictionary.txt";
	cout<<"Input the cipher text here --> "<<endl;
    getline(cin, cipher_text);


    CryptProcess obj(cipher_text, file_name);
    obj.decryption();

    return 0;
}

