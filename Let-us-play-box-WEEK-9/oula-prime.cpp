#include <iostream>
using namespace std;
#define MAX 1000
bool check[MAX+5]={false,};
int Prime[MAX+5]={0,};
int cnt=0;
void oula()
{
	for(int i = 2;i <= MAX;i++)
	{
		if(!check[i]) 
		{
			//记录,第X个质数是i
			Prime[++cnt]=i;
		}
		for(int j = 1;j <= cnt && i*Prime[j] <= MAX;j++)
		{
			check[i*Prime[j]] = true;
			if(i%Prime[j]==0) break;
		}
	}

}

int main()
{
	oula();
	int n = 29;
	cout<<"第"<<n<<"个质数是"<<Prime[n]<<endl;
	return 0;
}