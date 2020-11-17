//Вероятностное шифрование на RC5
//Санников Р., гр. ИТ-41

#include <cstring>
#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <iomanip>

using namespace std;

template <class WORD> class RC5
{
public:
	RC5(int r, int keyLength, const unsigned char* keyData);
	~RC5();
	pair<WORD, WORD> Encrypt_block(const pair<WORD, WORD> pt);
	pair<WORD, WORD> Decrypt_block(const pair<WORD, WORD> pt);
	vector<pair<WORD, WORD>> Encrypt(const vector<pair<WORD, WORD>> in);
	vector<pair<WORD, WORD>> Decrypt(const vector<pair<WORD, WORD>> in);
	vector<pair<WORD, WORD>> Probabilistic_Encrypt(const vector<pair<WORD, WORD>> in);
	vector<pair<WORD, WORD>> Probabilistic_Decrypt(const vector<pair<WORD, WORD>> in);
private:
	int w;
	int r;
	int b;
	int c;
	int sTableSize;
	WORD* S;
	WORD P;
	WORD Q;
	void KeyIninitialize(const unsigned char* keyData);
	WORD CyclicRightShift(WORD x, WORD y);
	WORD CyclicLeftShift(WORD x, WORD y);
};

template<class WORD>
RC5<WORD>::RC5(int r, int keyLength, const unsigned char* keyData)
{
	w = sizeof(WORD) * 8;
	b = keyLength;
	c = b * 8 / w;
	sTableSize = 2 * (r + 1);
	switch (sizeof(WORD))
	{
	case 2:
		P = (WORD)0xb7e1; //P(16) = 1011011111100001(2) = B7E1(16)
		Q = (WORD)0x9e37; //Q(16) = 1011011111100001(2) = 9E37(16)
		break;
	case 4:
		P = (WORD)0xb7e15163; //P(32) = 10110111111000010101000101100011(2) = B7E15163(16)
		Q = (WORD)0x9e3779b9; //Q(32) = 10011110001101110111100110111001(2) = 9E3779B9(16)
		break;
	case 8:
		P = (WORD)0xb7e151628aed2a6b; //P(64) = B7E151628AED2A6B(16)
		Q = (WORD)0x9e3779b97f4a7c15; //P(64) = 9E3779B97F4A&C15(16)
		break;
	default:
		break;
	}
	S = new WORD[sTableSize];
	KeyIninitialize(keyData);
}
template<class WORD>
RC5<WORD>::~RC5()
{
	delete[] S;
}
template<class WORD>
pair<WORD, WORD> RC5<WORD>::Encrypt_block(const pair<WORD, WORD> pt)
{
	int i;
	WORD A = pt.first + S[0], B = pt.second + S[1];
	for (i = 1; i <= r; i++)
	{
		A = CyclicLeftShift((WORD)(A ^ B), B) + S[2 * i];
		B = CyclicLeftShift((WORD)(B ^ A), A) + S[2 * i + 1];
	}
	return make_pair(A, B);
}
template<class WORD>
vector<pair<WORD, WORD>> RC5<WORD>::Encrypt(const vector<pair<WORD, WORD>> in)
{
	vector<pair<WORD, WORD>> out(in.size(), make_pair(0, 0));
	for (int i = 0; i < in.size(); i++) 
	{
		out[i] = Encrypt_block(in[i]);
	}
	return out;
}
template<class WORD>
vector<pair<WORD, WORD>> RC5<WORD>::Probabilistic_Encrypt(const vector<pair<WORD, WORD>> in)
{
	vector<pair<WORD, WORD>> out(in.size() * 2, make_pair(0, 0));
	for (int i = 0; i < in.size(); i++) 
	{
		pair<WORD, WORD> in_block = in[i];
		out[2 * i] = Encrypt_block(make_pair(in_block.first, (WORD)rand()));
		out[2 * i + 1] = Encrypt_block(make_pair(in_block.second, (WORD)rand()));
	}
	return out;
}
template<class WORD>
pair<WORD, WORD> RC5<WORD>::Decrypt_block(const pair<WORD, WORD> ct)
{
	int i;
	WORD B = ct.second, A = ct.first;
	for (i = r; i > 0; i--)
	{
		B = CyclicRightShift(B - S[2 * i + 1], A) ^ A;
		A = CyclicRightShift(A - S[2 * i], B) ^ B;
	}
	return make_pair(A - S[0], B - S[1]);
}
template<class WORD>
vector<pair<WORD, WORD>> RC5<WORD>::Decrypt(const vector<pair<WORD, WORD>> in)
{
	vector<pair<WORD, WORD>> out(in.size(), make_pair(0, 0));
	for (int i = 0; i < in.size(); i++) 
	{
		out[i] = Decrypt_block(in[i]);
	}
	return out;
}
template<class WORD>
vector<pair<WORD, WORD>> RC5<WORD>::Probabilistic_Decrypt(const vector<pair<WORD, WORD>> in)
{
	vector<pair<WORD, WORD>> out(in.size() / 2, make_pair(0, 0));
	for (int i = 0; i < out.size(); i++) 
	{
		pair<WORD, WORD> in_block_one = Decrypt_block(in[2 * i]);
		pair<WORD, WORD> in_block_two = Decrypt_block(in[2 * i + 1]);
		out[i] = make_pair(in_block_one.first, in_block_two.second);
	}
	return out;
}
template<class WORD>
void RC5<WORD>::KeyIninitialize(const unsigned char* keyData)
{
	int i, j, k;
	WORD A, B;
	WORD u = w / 8;
	WORD* L = new WORD[c];
	memset(L, 0, sizeof(L));
	for (i = b - 1; i != -1; i--)
		L[i / u] = (L[i / u] << 8) + keyData[i];
	for (i = 1, S[0] = P; i < sTableSize; i++)
		S[i] = S[i - 1] + Q;
	for (A = B = i = j = k = 0; k < 3 * sTableSize; k++)
	{
		A = S[i] = CyclicLeftShift(S[i] + (A + B), 3);
		B = L[j] = CyclicLeftShift(L[j] + (A + B), A + B);
		i = (i + 1) % sTableSize;
		j = (j + 1) % c;
	}
	delete[] L;
}

template<class WORD>
WORD RC5<WORD>::CyclicRightShift(WORD x, WORD y)
{
	return (x >> (y & (w - 1))) | (x << (w - (y & (w - 1))));
}

template<class WORD>
WORD RC5<WORD>::CyclicLeftShift(WORD x, WORD y)
{
	return (x << (y & (w - 1))) | (x >> (w - (y & (w - 1))));
}

int main()
{
	setlocale(LC_ALL, "Rus");
	const unsigned char key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	RC5<unsigned short> rc5(32, 12, key);
	int enter;
	while (true)
	{
		cout << "Введите 1 для шифрования, 2 для расшифровки, 3 для вероятностной кодировки, 4 для вероятностного декодирования" << endl;
		cin >> enter;
		switch (enter)
		{
		case 1:
		{
			int size;
			cin >> size;
			vector<pair<unsigned short, unsigned short>> input(size, make_pair(0, 0));
			for (int i = 0; i < size; i++) 
			{
				unsigned int in;
				cin >> in;
				input[i] = make_pair((unsigned short)in, (unsigned short)(in >> 16));
			}
			vector<pair<unsigned short, unsigned short>> output = rc5.Encrypt(input);
			for (int i = 0; i < output.size(); i++) 
			{
				unsigned int out = ((unsigned int)output[i].first) | (((unsigned int)(output[i].second)) << 16);
				cout << "Зашифровка: 0x" << hex << setfill('0') << setw(8) << out << endl;
			}
			break;
		}
		case 2:
		{
			int size;
			cin >> size;
			vector<pair<unsigned short, unsigned short>> input(size, make_pair(0, 0));
			for (int i = 0; i < size; i++) 
			{
				unsigned int in;
				cin >> in;
				input[i] = make_pair((unsigned short)in, (unsigned short)(in >> 16));
			}
			vector<pair<unsigned short, unsigned short>> output = rc5.Decrypt(input);
			for (int i = 0; i < output.size(); i++) 
			{
				unsigned int out = ((unsigned int)output[i].first) | (((unsigned int)(output[i].second)) << 16);
				cout << "Расшифровка: " << hex << setfill('0') << setw(8) << out << endl;
			}
			break;
			break;
		}
		case 3:
		{
			int size;
			cin >> size;
			vector<pair<unsigned short, unsigned short>> input(size, make_pair(0, 0));
			for (int i = 0; i < size; i++) 
			{
				unsigned int in;
				cin >> in;
				input[i] = make_pair((unsigned short)in, (unsigned short)(in >> 16));
			}
			vector<pair<unsigned short, unsigned short>> output = rc5.Probabilistic_Encrypt(input);
			for (int i = 0; i < output.size(); i++) 
			{
				unsigned int out = ((unsigned int)output[i].first) | (((unsigned int)(output[i].second)) << 16);
				cout << "Вероятностная кодировка: " << hex << setfill('0') << setw(8) << out << endl;
			}
			break;
		}
		case 4:
		{
			int size;
			cin >> size;
			vector<pair<unsigned short, unsigned short>> input(size, make_pair(0, 0));
			for (int i = 0; i < size; i++) 
			{
				unsigned int in;
				cin >> in;
				input[i] = make_pair((unsigned short)in, (unsigned short)(in >> 16));
			}
			vector<pair<unsigned short, unsigned short>> output = rc5.Probabilistic_Decrypt(input);
			for (int i = 0; i < output.size(); i++) 
			{
				unsigned int out = ((unsigned int)output[i].first) | (((unsigned int)(output[i].second)) << 16);
				cout << "Вероятностное декодирование: " << hex << setfill('0') << setw(8) << out << endl;
			}
			break;
			break;
		}
		default: 
		{
			cout << "Неверно введенные значения!" << endl;
		}
		}
	}
	system("pause");
	return 0;
}
