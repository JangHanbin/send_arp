//
//  printdata.hpp
//  EncodingTranslator
//
//  Created by 장한빈 on 2018. 7. 30..
//  Copyright © 2018년 장한빈. All rights reserved.
//

#ifndef printdata_hpp
#define printdata_hpp

#include <iostream>
#include <iomanip>

using namespace std;

void printLine();


void printByHexData(u_int8_t *printArr, int length);


void printByMAC(u_int8_t *printArr,int length);


#endif /* printdata_hpp */
