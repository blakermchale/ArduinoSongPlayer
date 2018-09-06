#include <stdio.h>

#define c2 65
#define C2 69
#define d2 73
#define D2 78
#define e2 82
#define f2 87
#define F2 92
#define g2 98
#define G2 104
#define la2 110
#define LA2 116
#define b2 123


enum PITCH{
    space,
    C,
    Cs,
    D,
    Ds,
    E,
    F,
    Fs,
    G,
    Gs,
    A,
    As,
    B
};
/*
enum BEATS{
    B1,
    B1_2,
    B1_3,
    B1_4,
    B2_3,
    B3_2,
    B2,
    B3


};
*/
typedef struct{

	int octave:4;
	int pitch:4;
	int beats:8;
	
} Note;

const int InterstellarLength = 832;

    #define BPM 70
    #define B1 60000/BPM //quarter note
    #define B1_2 B1/2
    #define B1_3 B1/3
    #define B1_4 B1/4
    #define B2_3 B1*2/3
    #define B3_2 3*B1/2
    #define B2 B1*2
    #define B3 B1*3
    
    Note notes[InterstellarLength];

    


//LiquidCrystal lcd(12, 11, 5, 4, 3, 2);
const int redPin = 8;
const int yellowPin = 12;
const int greenPin = 6;
const int bluePin = 10;
const int buzzerPin = 5;

int redButton, yellowButton, greenButton, blueButton;
//int sensorPin = A1;
int sensorValue;



void setup()
{

    //analogWrite(9, 105);
    //lcd.begin(16, 2);
    //lcd.clear();
    pinMode(13, OUTPUT);
    pinMode(11, OUTPUT);
    pinMode(9, OUTPUT);
    pinMode(7, OUTPUT);
    pinMode(buzzerPin, OUTPUT);
    //pinMode(redPin, INPUT_PULLUP);
    //pinMode(yellowPin, INPUT_PULLUP);
    //pinMode(greenPin, INPUT_PULLUP);
    pinMode(bluePin, INPUT_PULLUP);
    
    
    }

// notes[x] -> 

int get_frequency(int x)
{
	switch(notes[x].pitch)
    {
	  case space:
		    return 0;
	
    case C:
        return c2*(1<<(notes[x].octave-2));
	
		case D:
        return d2*(1<<(notes[x].octave-2));
        
    case E:
        return e2*(1<<(notes[x].octave-2));

    case F:
        return f2*(1<<(notes[x].octave-2));

    case G:
        return g2*(1<<(notes[x].octave-2));

    case A:
        return la2*(1<<(notes[x].octave-2));

    case B:
        return b2*(1<<(notes[x].octave-2));
	// add rest of cases
    }
}
	
void play(int songLength){
   
    int frequency;
   
    for (int x = 0; x < songLength; x++){

		frequency = get_frequency(x);
	
        if (!frequency)          // is this a rest?
            delay(notes[x].beats);            // then pause for a moment
        else                          // otherwise, play the note
        {
            tone(buzzerPin, frequency, notes[x].beats);
            delay(notes[x].beats);            // wait for tone to finish
        }
        delay(10);              // brief pause between notes
    }
}




  

void loop(){
    notes[0].octave = 5;
notes[0].pitch = E;
notes[0].beats = B1_2;

notes[1].octave = 0;
notes[1].pitch = space;
notes[1].beats = B1_2;

notes[2].octave = 5;
notes[2].pitch = E;
notes[2].beats = B1_2;

notes[3].octave = 0;
notes[3].pitch = space;
notes[3].beats = B1_2;

notes[4].octave = 5;
notes[4].pitch = E;
notes[4].beats = B1_2;

notes[5].octave = 0;
notes[5].pitch = space;
notes[5].beats = B1_2;

notes[6].octave = 5;
notes[6].pitch = E;
notes[6].beats = B1_2;

notes[7].octave = 0;
notes[7].pitch = space;
notes[7].beats = B1_2;

notes[8].octave = 5;
notes[8].pitch = E;
notes[8].beats = B1_2;

notes[9].octave = 0;
notes[9].pitch = space;
notes[9].beats = B1_2;

notes[10].octave = 5;
notes[10].pitch = E;
notes[10].beats = B1_2;

notes[11].octave = 0;
notes[11].pitch = space;
notes[11].beats = B1_2;

notes[12].octave = 4;
notes[12].pitch = A;
notes[12].beats = B1;

notes[13].octave = 5;
notes[13].pitch = E;
notes[13].beats = B1;

notes[14].octave = 4;
notes[14].pitch = E;
notes[14].beats = B1;

notes[15].octave = 4;
notes[15].pitch = A;
notes[15].beats = B1;

notes[16].octave = 5;
notes[16].pitch = E;
notes[16].beats = B1;

notes[17].octave = 4;
notes[17].pitch = E;
notes[17].beats = B1;

notes[18].octave = 4;
notes[18].pitch = B;
notes[18].beats = B1;

notes[19].octave = 5;
notes[19].pitch = E;
notes[19].beats = B1;

notes[20].octave = 4;
notes[20].pitch = E;
notes[20].beats = B1;

notes[21].octave = 4;
notes[21].pitch = B;
notes[21].beats = B1;

notes[22].octave = 5;
notes[22].pitch = E;
notes[22].beats = B1;

notes[23].octave = 4;
notes[23].pitch = E;
notes[23].beats = B1;

notes[24].octave = 5;
notes[24].pitch = C;
notes[24].beats = B1;

notes[25].octave = 5;
notes[25].pitch = E;
notes[25].beats = B1;

notes[26].octave = 4;
notes[26].pitch = E;
notes[26].beats = B1;

notes[27].octave = 5;
notes[27].pitch = C;
notes[27].beats = B1;

notes[28].octave = 5;
notes[28].pitch = E;
notes[28].beats = B1;

notes[29].octave = 4;
notes[29].pitch = E;
notes[29].beats = B1;

notes[30].octave = 5;
notes[30].pitch = D;
notes[30].beats = B1;

notes[31].octave = 5;
notes[31].pitch = E;
notes[31].beats = B1;

notes[32].octave = 4;
notes[32].pitch = E;
notes[32].beats = B1;

notes[33].octave = 5;
notes[33].pitch = D;
notes[33].beats = B1;

notes[34].octave = 5;
notes[34].pitch = E;
notes[34].beats = B1;

notes[35].octave = 4;
notes[35].pitch = B;
notes[35].beats = B1;

notes[36].octave = 4;
notes[36].pitch = A;
notes[36].beats = B1;

notes[37].octave = 5;
notes[37].pitch = E;
notes[37].beats = B1_2;

notes[38].octave = 5;
notes[38].pitch = E;
notes[38].beats = B1_2;

notes[39].octave = 5;
notes[39].pitch = E;
notes[39].beats = B1_2;

notes[40].octave = 5;
notes[40].pitch = E;
notes[40].beats = B1_2;

notes[41].octave = 4;
notes[41].pitch = A;
notes[41].beats = B1;

notes[42].octave = 5;
notes[42].pitch = E;
notes[42].beats = B1_2;

notes[43].octave = 5;
notes[43].pitch = E;
notes[43].beats = B1_2;

notes[44].octave = 5;
notes[44].pitch = E;
notes[44].beats = B1_2;

notes[45].octave = 5;
notes[45].pitch = E;
notes[45].beats = B1_2;

notes[46].octave = 4;
notes[46].pitch = B;
notes[46].beats = B1;

notes[47].octave = 5;
notes[47].pitch = E;
notes[47].beats = B1_2;

notes[48].octave = 5;
notes[48].pitch = E;
notes[48].beats = B1_2;

notes[49].octave = 5;
notes[49].pitch = E;
notes[49].beats = B1_2;

notes[50].octave = 5;
notes[50].pitch = E;
notes[50].beats = B1_2;

notes[51].octave = 4;
notes[51].pitch = B;
notes[51].beats = B1;

notes[52].octave = 5;
notes[52].pitch = E;
notes[52].beats = B1_2;

notes[53].octave = 5;
notes[53].pitch = E;
notes[53].beats = B1_2;

notes[54].octave = 5;
notes[54].pitch = E;
notes[54].beats = B1_2;

notes[55].octave = 5;
notes[55].pitch = E;
notes[55].beats = B1_2;

notes[56].octave = 5;
notes[56].pitch = C;
notes[56].beats = B1;

notes[57].octave = 5;
notes[57].pitch = E;
notes[57].beats = B1_2;

notes[58].octave = 5;
notes[58].pitch = E;
notes[58].beats = B1_2;

notes[59].octave = 5;
notes[59].pitch = E;
notes[59].beats = B1_2;

notes[60].octave = 5;
notes[60].pitch = E;
notes[60].beats = B1_2;

notes[61].octave = 5;
notes[61].pitch = C;
notes[61].beats = B1;

notes[62].octave = 5;
notes[62].pitch = E;
notes[62].beats = B1_2;

notes[63].octave = 5;
notes[63].pitch = E;
notes[63].beats = B1_2;

notes[64].octave = 5;
notes[64].pitch = E;
notes[64].beats = B1_2;

notes[65].octave = 5;
notes[65].pitch = E;
notes[65].beats = B1_2;

notes[66].octave = 5;
notes[66].pitch = D;
notes[66].beats = B1;

notes[67].octave = 5;
notes[67].pitch = E;
notes[67].beats = B1_2;

notes[68].octave = 5;
notes[68].pitch = E;
notes[68].beats = B1_2;

notes[69].octave = 5;
notes[69].pitch = E;
notes[69].beats = B1_2;

notes[70].octave = 5;
notes[70].pitch = E;
notes[70].beats = B1_2;

notes[71].octave = 5;
notes[71].pitch = D;
notes[71].beats = B1;

notes[72].octave = 5;
notes[72].pitch = E;
notes[72].beats = B1_2;

notes[73].octave = 5;
notes[73].pitch = E;
notes[73].beats = B1_2;

notes[74].octave = 5;
notes[74].pitch = E;
notes[74].beats = B1_2;

notes[75].octave = 5;
notes[75].pitch = E;
notes[75].beats = B1_2;

notes[76].octave = 5;
notes[76].pitch = B;
notes[76].beats = B1_4;

notes[77].octave = 6;
notes[77].pitch = C;
notes[77].beats = B1_4;

notes[78].octave = 5;
notes[78].pitch = B;
notes[78].beats = B1_4;

notes[79].octave = 6;
notes[79].pitch = C;
notes[79].beats = B1_4;

notes[80].octave = 5;
notes[80].pitch = B;
notes[80].beats = B1_4;

notes[81].octave = 6;
notes[81].pitch = C;
notes[81].beats = B1_4;

notes[82].octave = 5;
notes[82].pitch = B;
notes[82].beats = B1_4;

notes[83].octave = 6;
notes[83].pitch = C;
notes[83].beats = B1_4;

notes[84].octave = 5;
notes[84].pitch = B;
notes[84].beats = B1_4;

notes[85].octave = 6;
notes[85].pitch = C;
notes[85].beats = B1_4;

notes[86].octave = 5;
notes[86].pitch = B;
notes[86].beats = B1_4;

notes[87].octave = 6;
notes[87].pitch = C;
notes[87].beats = B1_4;

notes[88].octave = 5;
notes[88].pitch = B;
notes[88].beats = B1_4;

notes[89].octave = 6;
notes[89].pitch = C;
notes[89].beats = B1_4;

notes[90].octave = 5;
notes[90].pitch = B;
notes[90].beats = B1_4;

notes[91].octave = 6;
notes[91].pitch = C;
notes[91].beats = B1_4;

notes[92].octave = 5;
notes[92].pitch = B;
notes[92].beats = B1_4;

notes[93].octave = 6;
notes[93].pitch = C;
notes[93].beats = B1_4;

notes[94].octave = 5;
notes[94].pitch = B;
notes[94].beats = B1_4;

notes[95].octave = 6;
notes[95].pitch = C;
notes[95].beats = B1_4;

notes[96].octave = 5;
notes[96].pitch = B;
notes[96].beats = B1_4;

notes[97].octave = 6;
notes[97].pitch = C;
notes[97].beats = B1_4;

notes[98].octave = 5;
notes[98].pitch = B;
notes[98].beats = B1_4;

notes[99].octave = 6;
notes[99].pitch = C;
notes[99].beats = B1_4;

notes[100].octave = 5;
notes[100].pitch = B;
notes[100].beats = B1_4;

notes[101].octave = 6;
notes[101].pitch = C;
notes[101].beats = B1_4;

notes[102].octave = 5;
notes[102].pitch = B;
notes[102].beats = B1_4;

notes[103].octave = 6;
notes[103].pitch = C;
notes[103].beats = B1_4;

notes[104].octave = 5;
notes[104].pitch = B;
notes[104].beats = B1_4;

notes[105].octave = 6;
notes[105].pitch = C;
notes[105].beats = B1_4;

notes[106].octave = 5;
notes[106].pitch = B;
notes[106].beats = B1_4;

notes[107].octave = 6;
notes[107].pitch = C;
notes[107].beats = B1_4;

notes[108].octave = 5;
notes[108].pitch = B;
notes[108].beats = B1_4;

notes[109].octave = 6;
notes[109].pitch = C;
notes[109].beats = B1_4;

notes[110].octave = 5;
notes[110].pitch = B;
notes[110].beats = B1_4;

notes[111].octave = 6;
notes[111].pitch = C;
notes[111].beats = B1_4;

notes[112].octave = 5;
notes[112].pitch = B;
notes[112].beats = B1_4;

notes[113].octave = 6;
notes[113].pitch = C;
notes[113].beats = B1_4;

notes[114].octave = 5;
notes[114].pitch = B;
notes[114].beats = B1_4;

notes[115].octave = 6;
notes[115].pitch = C;
notes[115].beats = B1_4;

notes[116].octave = 5;
notes[116].pitch = B;
notes[116].beats = B1_4;

notes[117].octave = 6;
notes[117].pitch = C;
notes[117].beats = B1_4;

notes[118].octave = 5;
notes[118].pitch = B;
notes[118].beats = B1_4;

notes[119].octave = 6;
notes[119].pitch = C;
notes[119].beats = B1_4;

notes[120].octave = 5;
notes[120].pitch = B;
notes[120].beats = B1_4;

notes[121].octave = 6;
notes[121].pitch = C;
notes[121].beats = B1_4;

notes[122].octave = 5;
notes[122].pitch = B;
notes[122].beats = B1_4;

notes[123].octave = 6;
notes[123].pitch = C;
notes[123].beats = B1_4;

notes[124].octave = 5;
notes[124].pitch = B;
notes[124].beats = B1_4;

notes[125].octave = 6;
notes[125].pitch = C;
notes[125].beats = B1_4;

notes[126].octave = 5;
notes[126].pitch = B;
notes[126].beats = B1_4;

notes[127].octave = 6;
notes[127].pitch = C;
notes[127].beats = B1_4;

notes[128].octave = 5;
notes[128].pitch = B;
notes[128].beats = B1_4;

notes[129].octave = 6;
notes[129].pitch = C;
notes[129].beats = B1_4;

notes[130].octave = 5;
notes[130].pitch = B;
notes[130].beats = B1_4;

notes[131].octave = 6;
notes[131].pitch = C;
notes[131].beats = B1_4;

notes[132].octave = 5;
notes[132].pitch = B;
notes[132].beats = B1_4;

notes[133].octave = 6;
notes[133].pitch = C;
notes[133].beats = B1_4;

notes[134].octave = 5;
notes[134].pitch = B;
notes[134].beats = B1_4;

notes[135].octave = 6;
notes[135].pitch = C;
notes[135].beats = B1_4;

notes[136].octave = 5;
notes[136].pitch = A;
notes[136].beats = B1;

notes[137].octave = 6;
notes[137].pitch = E;
notes[137].beats = B2;

notes[138].octave = 5;
notes[138].pitch = A;
notes[138].beats = B1;

notes[139].octave = 6;
notes[139].pitch = E;
notes[139].beats = B2;

notes[140].octave = 5;
notes[140].pitch = A;
notes[140].beats = B1;

notes[141].octave = 6;
notes[141].pitch = E;
notes[141].beats = B2;

notes[142].octave = 5;
notes[142].pitch = A;
notes[142].beats = B1;

notes[143].octave = 6;
notes[143].pitch = E;
notes[143].beats = B2;

notes[144].octave = 6;
notes[144].pitch = C;
notes[144].beats = B1;

notes[145].octave = 6;
notes[145].pitch = E;
notes[145].beats = B2;

notes[146].octave = 6;
notes[146].pitch = C;
notes[146].beats = B1;

notes[147].octave = 6;
notes[147].pitch = E;
notes[147].beats = B2;

notes[148].octave = 6;
notes[148].pitch = C;
notes[148].beats = B1;

notes[149].octave = 6;
notes[149].pitch = E;
notes[149].beats = B2;

notes[150].octave = 6;
notes[150].pitch = D;
notes[150].beats = B1;

notes[151].octave = 6;
notes[151].pitch = E;
notes[151].beats = B1;

notes[152].octave = 5;
notes[152].pitch = B;
notes[152].beats = B1;

notes[153].octave = 5;
notes[153].pitch = A;
notes[153].beats = B1;

notes[154].octave = 6;
notes[154].pitch = E;
notes[154].beats = B2;

notes[155].octave = 5;
notes[155].pitch = A;
notes[155].beats = B1;

notes[156].octave = 6;
notes[156].pitch = E;
notes[156].beats = B2;

notes[157].octave = 5;
notes[157].pitch = B;
notes[157].beats = B1;

notes[158].octave = 6;
notes[158].pitch = E;
notes[158].beats = B2;

notes[159].octave = 5;
notes[159].pitch = B;
notes[159].beats = B1;

notes[160].octave = 6;
notes[160].pitch = E;
notes[160].beats = B2;

notes[161].octave = 6;
notes[161].pitch = C;
notes[161].beats = B1;

notes[162].octave = 6;
notes[162].pitch = E;
notes[162].beats = B2;

notes[163].octave = 6;
notes[163].pitch = C;
notes[163].beats = B1;

notes[164].octave = 6;
notes[164].pitch = E;
notes[164].beats = B2;

notes[165].octave = 6;
notes[165].pitch = D;
notes[165].beats = B1;

notes[166].octave = 6;
notes[166].pitch = E;
notes[166].beats = B2;

notes[167].octave = 6;
notes[167].pitch = D;
notes[167].beats = B1;

notes[168].octave = 6;
notes[168].pitch = E;
notes[168].beats = B1;

notes[169].octave = 5;
notes[169].pitch = B;
notes[169].beats = B1;

notes[170].octave = 3;
notes[170].pitch = A;
notes[170].beats = B1_4;

notes[171].octave = 3;
notes[171].pitch = F;
notes[171].beats = B1_4;

notes[172].octave = 3;
notes[172].pitch = E;
notes[172].beats = B1_4;

notes[173].octave = 3;
notes[173].pitch = C;
notes[173].beats = B1_4;

notes[174].octave = 0;
notes[174].pitch = space;
notes[174].beats = B1_4;

notes[175].octave = 3;
notes[175].pitch = C;
notes[175].beats = B1_4;

notes[176].octave = 3;
notes[176].pitch = E;
notes[176].beats = B1_4;

notes[177].octave = 3;
notes[177].pitch = F;
notes[177].beats = B1_4;

notes[178].octave = 3;
notes[178].pitch = A;
notes[178].beats = B1_4;

notes[179].octave = 3;
notes[179].pitch = F;
notes[179].beats = B1_4;

notes[180].octave = 3;
notes[180].pitch = E;
notes[180].beats = B1_4;

notes[181].octave = 3;
notes[181].pitch = C;
notes[181].beats = B1_4;

notes[182].octave = 3;
notes[182].pitch = A;
notes[182].beats = B1_4;

notes[183].octave = 3;
notes[183].pitch = F;
notes[183].beats = B1_4;

notes[184].octave = 3;
notes[184].pitch = E;
notes[184].beats = B1_4;

notes[185].octave = 3;
notes[185].pitch = C;
notes[185].beats = B1_4;

notes[186].octave = 0;
notes[186].pitch = space;
notes[186].beats = B1_4;

notes[187].octave = 3;
notes[187].pitch = C;
notes[187].beats = B1_4;

notes[188].octave = 3;
notes[188].pitch = E;
notes[188].beats = B1_4;

notes[189].octave = 3;
notes[189].pitch = F;
notes[189].beats = B1_4;

notes[190].octave = 3;
notes[190].pitch = A;
notes[190].beats = B1_4;

notes[191].octave = 3;
notes[191].pitch = F;
notes[191].beats = B1_4;

notes[192].octave = 3;
notes[192].pitch = E;
notes[192].beats = B1_4;

notes[193].octave = 3;
notes[193].pitch = C;
notes[193].beats = B1_4;

notes[194].octave = 3;
notes[194].pitch = B;
notes[194].beats = B1_4;

notes[195].octave = 3;
notes[195].pitch = E;
notes[195].beats = B1_4;

notes[196].octave = 3;
notes[196].pitch = D;
notes[196].beats = B1_4;

notes[197].octave = 2;
notes[197].pitch = B;
notes[197].beats = B1_4;

notes[198].octave = 0;
notes[198].pitch = space;
notes[198].beats = B1_4;

notes[199].octave = 2;
notes[199].pitch = B;
notes[199].beats = B1_4;

notes[200].octave = 3;
notes[200].pitch = D;
notes[200].beats = B1_4;

notes[201].octave = 3;
notes[201].pitch = E;
notes[201].beats = B1_4;

notes[202].octave = 3;
notes[202].pitch = B;
notes[202].beats = B1_4;

notes[203].octave = 3;
notes[203].pitch = E;
notes[203].beats = B1_4;

notes[204].octave = 3;
notes[204].pitch = D;
notes[204].beats = B1_4;

notes[205].octave = 2;
notes[205].pitch = B;
notes[205].beats = B1_4;

notes[206].octave = 3;
notes[206].pitch = B;
notes[206].beats = B1_4;

notes[207].octave = 3;
notes[207].pitch = E;
notes[207].beats = B1_4;

notes[208].octave = 3;
notes[208].pitch = D;
notes[208].beats = B1_4;

notes[209].octave = 2;
notes[209].pitch = B;
notes[209].beats = B1_4;

notes[210].octave = 0;
notes[210].pitch = space;
notes[210].beats = B1_4;

notes[211].octave = 2;
notes[211].pitch = B;
notes[211].beats = B1_4;

notes[212].octave = 3;
notes[212].pitch = D;
notes[212].beats = B1_4;

notes[213].octave = 3;
notes[213].pitch = E;
notes[213].beats = B1_4;

notes[214].octave = 3;
notes[214].pitch = B;
notes[214].beats = B1_4;

notes[215].octave = 3;
notes[215].pitch = E;
notes[215].beats = B1_4;

notes[216].octave = 3;
notes[216].pitch = D;
notes[216].beats = B1_4;

notes[217].octave = 2;
notes[217].pitch = B;
notes[217].beats = B1_4;

notes[218].octave = 4;
notes[218].pitch = C;
notes[218].beats = B1_4;

notes[219].octave = 3;
notes[219].pitch = A;
notes[219].beats = B1_4;

notes[220].octave = 3;
notes[220].pitch = E;
notes[220].beats = B1_4;

notes[221].octave = 3;
notes[221].pitch = C;
notes[221].beats = B1_4;

notes[222].octave = 0;
notes[222].pitch = space;
notes[222].beats = B1_4;

notes[223].octave = 3;
notes[223].pitch = C;
notes[223].beats = B1_4;

notes[224].octave = 3;
notes[224].pitch = E;
notes[224].beats = B1_4;

notes[225].octave = 3;
notes[225].pitch = A;
notes[225].beats = B1_4;

notes[226].octave = 4;
notes[226].pitch = C;
notes[226].beats = B1_4;

notes[227].octave = 3;
notes[227].pitch = A;
notes[227].beats = B1_4;

notes[228].octave = 3;
notes[228].pitch = E;
notes[228].beats = B1_4;

notes[229].octave = 3;
notes[229].pitch = C;
notes[229].beats = B1_4;

notes[230].octave = 4;
notes[230].pitch = C;
notes[230].beats = B1_4;

notes[231].octave = 3;
notes[231].pitch = A;
notes[231].beats = B1_4;

notes[232].octave = 3;
notes[232].pitch = E;
notes[232].beats = B1_4;

notes[233].octave = 3;
notes[233].pitch = C;
notes[233].beats = B1_4;

notes[234].octave = 0;
notes[234].pitch = space;
notes[234].beats = B1_4;

notes[235].octave = 3;
notes[235].pitch = C;
notes[235].beats = B1_4;

notes[236].octave = 3;
notes[236].pitch = E;
notes[236].beats = B1_4;

notes[237].octave = 3;
notes[237].pitch = A;
notes[237].beats = B1_4;

notes[238].octave = 4;
notes[238].pitch = C;
notes[238].beats = B1_4;

notes[239].octave = 3;
notes[239].pitch = A;
notes[239].beats = B1_4;

notes[240].octave = 3;
notes[240].pitch = E;
notes[240].beats = B1_4;

notes[241].octave = 3;
notes[241].pitch = C;
notes[241].beats = B1_4;

notes[242].octave = 4;
notes[242].pitch = A;
notes[242].beats = B1_4;

notes[243].octave = 4;
notes[243].pitch = F;
notes[243].beats = B1_4;

notes[244].octave = 4;
notes[244].pitch = E;
notes[244].beats = B1_4;

notes[245].octave = 4;
notes[245].pitch = C;
notes[245].beats = B1_4;

notes[246].octave = 0;
notes[246].pitch = space;
notes[246].beats = B1_4;

notes[247].octave = 4;
notes[247].pitch = C;
notes[247].beats = B1_4;

notes[248].octave = 4;
notes[248].pitch = E;
notes[248].beats = B1_4;

notes[249].octave = 4;
notes[249].pitch = F;
notes[249].beats = B1_4;

notes[250].octave = 4;
notes[250].pitch = A;
notes[250].beats = B1_4;

notes[251].octave = 4;
notes[251].pitch = F;
notes[251].beats = B1_4;

notes[252].octave = 4;
notes[252].pitch = E;
notes[252].beats = B1_4;

notes[253].octave = 4;
notes[253].pitch = C;
notes[253].beats = B1_4;

notes[254].octave = 4;
notes[254].pitch = A;
notes[254].beats = B1_4;

notes[255].octave = 4;
notes[255].pitch = F;
notes[255].beats = B1_4;

notes[256].octave = 4;
notes[256].pitch = E;
notes[256].beats = B1_4;

notes[257].octave = 4;
notes[257].pitch = C;
notes[257].beats = B1_4;

notes[258].octave = 0;
notes[258].pitch = space;
notes[258].beats = B1_4;

notes[259].octave = 4;
notes[259].pitch = C;
notes[259].beats = B1_4;

notes[260].octave = 4;
notes[260].pitch = E;
notes[260].beats = B1_4;

notes[261].octave = 4;
notes[261].pitch = F;
notes[261].beats = B1_4;

notes[262].octave = 4;
notes[262].pitch = A;
notes[262].beats = B1_4;

notes[263].octave = 4;
notes[263].pitch = F;
notes[263].beats = B1_4;

notes[264].octave = 4;
notes[264].pitch = E;
notes[264].beats = B1_4;

notes[265].octave = 4;
notes[265].pitch = C;
notes[265].beats = B1_4;

notes[266].octave = 4;
notes[266].pitch = B;
notes[266].beats = B1_4;

notes[267].octave = 4;
notes[267].pitch = E;
notes[267].beats = B1_4;

notes[268].octave = 4;
notes[268].pitch = D;
notes[268].beats = B1_4;

notes[269].octave = 3;
notes[269].pitch = B;
notes[269].beats = B1_4;

notes[270].octave = 0;
notes[270].pitch = space;
notes[270].beats = B1_4;

notes[271].octave = 3;
notes[271].pitch = B;
notes[271].beats = B1_4;

notes[272].octave = 4;
notes[272].pitch = D;
notes[272].beats = B1_4;

notes[273].octave = 4;
notes[273].pitch = E;
notes[273].beats = B1_4;

notes[274].octave = 4;
notes[274].pitch = B;
notes[274].beats = B1_4;

notes[275].octave = 4;
notes[275].pitch = E;
notes[275].beats = B1_4;

notes[276].octave = 4;
notes[276].pitch = D;
notes[276].beats = B1_4;

notes[277].octave = 3;
notes[277].pitch = B;
notes[277].beats = B1_4;

notes[278].octave = 4;
notes[278].pitch = B;
notes[278].beats = B1_4;

notes[279].octave = 4;
notes[279].pitch = E;
notes[279].beats = B1_4;

notes[280].octave = 4;
notes[280].pitch = D;
notes[280].beats = B1_4;

notes[281].octave = 3;
notes[281].pitch = B;
notes[281].beats = B1_4;

notes[282].octave = 0;
notes[282].pitch = space;
notes[282].beats = B1_4;

notes[283].octave = 3;
notes[283].pitch = B;
notes[283].beats = B1_4;

notes[284].octave = 4;
notes[284].pitch = D;
notes[284].beats = B1_4;

notes[285].octave = 4;
notes[285].pitch = E;
notes[285].beats = B1_4;

notes[286].octave = 4;
notes[286].pitch = B;
notes[286].beats = B1_4;

notes[287].octave = 4;
notes[287].pitch = E;
notes[287].beats = B1_4;

notes[288].octave = 4;
notes[288].pitch = D;
notes[288].beats = B1_4;

notes[289].octave = 3;
notes[289].pitch = B;
notes[289].beats = B1_4;

notes[290].octave = 5;
notes[290].pitch = C;
notes[290].beats = B1_4;

notes[291].octave = 4;
notes[291].pitch = A;
notes[291].beats = B1_4;

notes[292].octave = 4;
notes[292].pitch = E;
notes[292].beats = B1_4;

notes[293].octave = 4;
notes[293].pitch = C;
notes[293].beats = B1_4;

notes[294].octave = 0;
notes[294].pitch = space;
notes[294].beats = B1_4;

notes[295].octave = 4;
notes[295].pitch = C;
notes[295].beats = B1_4;

notes[296].octave = 4;
notes[296].pitch = E;
notes[296].beats = B1_4;

notes[297].octave = 4;
notes[297].pitch = A;
notes[297].beats = B1_4;

notes[298].octave = 5;
notes[298].pitch = C;
notes[298].beats = B1_4;

notes[299].octave = 4;
notes[299].pitch = A;
notes[299].beats = B1_4;

notes[300].octave = 4;
notes[300].pitch = E;
notes[300].beats = B1_4;

notes[301].octave = 4;
notes[301].pitch = C;
notes[301].beats = B1_4;

notes[302].octave = 5;
notes[302].pitch = C;
notes[302].beats = B1_4;

notes[303].octave = 4;
notes[303].pitch = A;
notes[303].beats = B1_4;

notes[304].octave = 4;
notes[304].pitch = E;
notes[304].beats = B1_4;

notes[305].octave = 4;
notes[305].pitch = C;
notes[305].beats = B1_4;

notes[306].octave = 0;
notes[306].pitch = space;
notes[306].beats = B1_4;

notes[307].octave = 4;
notes[307].pitch = C;
notes[307].beats = B1_4;

notes[308].octave = 4;
notes[308].pitch = E;
notes[308].beats = B1_4;

notes[309].octave = 4;
notes[309].pitch = A;
notes[309].beats = B1_4;

notes[310].octave = 5;
notes[310].pitch = C;
notes[310].beats = B1_4;

notes[311].octave = 4;
notes[311].pitch = A;
notes[311].beats = B1_4;

notes[312].octave = 4;
notes[312].pitch = E;
notes[312].beats = B1_4;

notes[313].octave = 4;
notes[313].pitch = C;
notes[313].beats = B1_4;

notes[314].octave = 5;
notes[314].pitch = D;
notes[314].beats = B1_4;

notes[315].octave = 4;
notes[315].pitch = G;
notes[315].beats = B1_4;

notes[316].octave = 4;
notes[316].pitch = E;
notes[316].beats = B1_4;

notes[317].octave = 4;
notes[317].pitch = D;
notes[317].beats = B1_4;

notes[318].octave = 0;
notes[318].pitch = space;
notes[318].beats = B1_4;

notes[319].octave = 4;
notes[319].pitch = D;
notes[319].beats = B1_4;

notes[320].octave = 4;
notes[320].pitch = E;
notes[320].beats = B1_4;

notes[321].octave = 4;
notes[321].pitch = G;
notes[321].beats = B1_4;

notes[322].octave = 5;
notes[322].pitch = D;
notes[322].beats = B1_4;

notes[323].octave = 4;
notes[323].pitch = G;
notes[323].beats = B1_4;

notes[324].octave = 4;
notes[324].pitch = E;
notes[324].beats = B1_4;

notes[325].octave = 4;
notes[325].pitch = D;
notes[325].beats = B1_4;

notes[326].octave = 5;
notes[326].pitch = D;
notes[326].beats = B1_4;

notes[327].octave = 4;
notes[327].pitch = G;
notes[327].beats = B1_4;

notes[328].octave = 4;
notes[328].pitch = E;
notes[328].beats = B1_4;

notes[329].octave = 4;
notes[329].pitch = D;
notes[329].beats = B1_4;

notes[330].octave = 0;
notes[330].pitch = space;
notes[330].beats = B1_4;

notes[331].octave = 4;
notes[331].pitch = D;
notes[331].beats = B1_4;

notes[332].octave = 4;
notes[332].pitch = E;
notes[332].beats = B1_4;

notes[333].octave = 4;
notes[333].pitch = G;
notes[333].beats = B1_4;

notes[334].octave = 5;
notes[334].pitch = D;
notes[334].beats = B1_4;

notes[335].octave = 4;
notes[335].pitch = G;
notes[335].beats = B1_4;

notes[336].octave = 4;
notes[336].pitch = E;
notes[336].beats = B1_4;

notes[337].octave = 4;
notes[337].pitch = D;
notes[337].beats = B1_4;

notes[338].octave = 5;
notes[338].pitch = C;
notes[338].beats = B1_4;

notes[339].octave = 5;
notes[339].pitch = D;
notes[339].beats = B1_4;

notes[340].octave = 5;
notes[340].pitch = E;
notes[340].beats = B1_4;

notes[341].octave = 5;
notes[341].pitch = F;
notes[341].beats = B1_4;

notes[342].octave = 5;
notes[342].pitch = E;
notes[342].beats = B1_4;

notes[343].octave = 5;
notes[343].pitch = D;
notes[343].beats = B1_4;

notes[344].octave = 5;
notes[344].pitch = E;
notes[344].beats = B1_4;

notes[345].octave = 5;
notes[345].pitch = C;
notes[345].beats = B1_4;

notes[346].octave = 5;
notes[346].pitch = D;
notes[346].beats = B1_4;

notes[347].octave = 5;
notes[347].pitch = E;
notes[347].beats = B1_4;

notes[348].octave = 5;
notes[348].pitch = F;
notes[348].beats = B1_4;

notes[349].octave = 5;
notes[349].pitch = G;
notes[349].beats = B1_4;

notes[350].octave = 5;
notes[350].pitch = D;
notes[350].beats = B1_4;

notes[351].octave = 5;
notes[351].pitch = E;
notes[351].beats = B1_4;

notes[352].octave = 5;
notes[352].pitch = F;
notes[352].beats = B1_4;

notes[353].octave = 5;
notes[353].pitch = G;
notes[353].beats = B1_4;

notes[354].octave = 5;
notes[354].pitch = A;
notes[354].beats = B1_4;

notes[355].octave = 5;
notes[355].pitch = G;
notes[355].beats = B1_4;

notes[356].octave = 5;
notes[356].pitch = F;
notes[356].beats = B1_4;

notes[357].octave = 5;
notes[357].pitch = E;
notes[357].beats = B1_4;

notes[358].octave = 5;
notes[358].pitch = F;
notes[358].beats = B1_4;

notes[359].octave = 5;
notes[359].pitch = G;
notes[359].beats = B1_4;

notes[360].octave = 5;
notes[360].pitch = A;
notes[360].beats = B1_4;

notes[361].octave = 5;
notes[361].pitch = B;
notes[361].beats = B1_4;

notes[362].octave = 6;
notes[362].pitch = C;
notes[362].beats = B1_4;

notes[363].octave = 5;
notes[363].pitch = B;
notes[363].beats = B1_4;

notes[364].octave = 5;
notes[364].pitch = A;
notes[364].beats = B1_4;

notes[365].octave = 5;
notes[365].pitch = B;
notes[365].beats = B1_4;

notes[366].octave = 5;
notes[366].pitch = G;
notes[366].beats = B1_4;

notes[367].octave = 5;
notes[367].pitch = A;
notes[367].beats = B1_4;

notes[368].octave = 5;
notes[368].pitch = B;
notes[368].beats = B1_4;

notes[369].octave = 5;
notes[369].pitch = E;
notes[369].beats = B1_4;

notes[370].octave = 5;
notes[370].pitch = B;
notes[370].beats = B1_4;

notes[371].octave = 5;
notes[371].pitch = G;
notes[371].beats = B1_4;

notes[372].octave = 5;
notes[372].pitch = A;
notes[372].beats = B1_4;

notes[373].octave = 5;
notes[373].pitch = G;
notes[373].beats = B1_4;

notes[374].octave = 5;
notes[374].pitch = A;
notes[374].beats = B1_4;

notes[375].octave = 5;
notes[375].pitch = B;
notes[375].beats = B1_4;

notes[376].octave = 6;
notes[376].pitch = D;
notes[376].beats = B1_4;

notes[377].octave = 5;
notes[377].pitch = E;
notes[377].beats = B1_4;

notes[378].octave = 5;
notes[378].pitch = G;
notes[378].beats = B1_4;

notes[379].octave = 5;
notes[379].pitch = A;
notes[379].beats = B1_4;

notes[380].octave = 5;
notes[380].pitch = B;
notes[380].beats = B1_4;

notes[381].octave = 5;
notes[381].pitch = G;
notes[381].beats = B1_4;

notes[382].octave = 5;
notes[382].pitch = A;
notes[382].beats = B1_4;

notes[383].octave = 5;
notes[383].pitch = B;
notes[383].beats = B1_4;

notes[384].octave = 6;
notes[384].pitch = D;
notes[384].beats = B1_4;

notes[385].octave = 5;
notes[385].pitch = E;
notes[385].beats = B1_4;

notes[386].octave = 6;
notes[386].pitch = C;
notes[386].beats = B1_4;

notes[387].octave = 5;
notes[387].pitch = B;
notes[387].beats = B1_4;

notes[388].octave = 6;
notes[388].pitch = C;
notes[388].beats = B1_4;

notes[389].octave = 5;
notes[389].pitch = A;
notes[389].beats = B1_4;

notes[390].octave = 5;
notes[390].pitch = B;
notes[390].beats = B1_4;

notes[391].octave = 6;
notes[391].pitch = C;
notes[391].beats = B1_4;

notes[392].octave = 6;
notes[392].pitch = D;
notes[392].beats = B1_4;

notes[393].octave = 5;
notes[393].pitch = A;
notes[393].beats = B1_4;

notes[394].octave = 6;
notes[394].pitch = C;
notes[394].beats = B1_4;

notes[395].octave = 5;
notes[395].pitch = B;
notes[395].beats = B1_4;

notes[396].octave = 6;
notes[396].pitch = C;
notes[396].beats = B1_4;

notes[397].octave = 5;
notes[397].pitch = A;
notes[397].beats = B1_4;

notes[398].octave = 5;
notes[398].pitch = B;
notes[398].beats = B1_4;

notes[399].octave = 6;
notes[399].pitch = C;
notes[399].beats = B1_4;

notes[400].octave = 6;
notes[400].pitch = D;
notes[400].beats = B1_4;

notes[401].octave = 5;
notes[401].pitch = A;
notes[401].beats = B1_4;

notes[402].octave = 6;
notes[402].pitch = C;
notes[402].beats = B1_4;

notes[403].octave = 5;
notes[403].pitch = B;
notes[403].beats = B1_4;

notes[404].octave = 6;
notes[404].pitch = C;
notes[404].beats = B1_4;

notes[405].octave = 5;
notes[405].pitch = A;
notes[405].beats = B1_4;

notes[406].octave = 5;
notes[406].pitch = E;
notes[406].beats = B1_4;

notes[407].octave = 6;
notes[407].pitch = C;
notes[407].beats = B1_4;

notes[408].octave = 5;
notes[408].pitch = B;
notes[408].beats = B1_4;

notes[409].octave = 6;
notes[409].pitch = C;
notes[409].beats = B1_4;

notes[410].octave = 5;
notes[410].pitch = A;
notes[410].beats = B1_4;

notes[411].octave = 5;
notes[411].pitch = B;
notes[411].beats = B1_4;

notes[412].octave = 6;
notes[412].pitch = C;
notes[412].beats = B1_4;

notes[413].octave = 6;
notes[413].pitch = D;
notes[413].beats = B1_4;

notes[414].octave = 6;
notes[414].pitch = C;
notes[414].beats = B1_4;

notes[415].octave = 5;
notes[415].pitch = B;
notes[415].beats = B1_4;

notes[416].octave = 6;
notes[416].pitch = C;
notes[416].beats = B1_4;

notes[417].octave = 6;
notes[417].pitch = D;
notes[417].beats = B1_4;

notes[418].octave = 6;
notes[418].pitch = E;
notes[418].beats = B1_4;

notes[419].octave = 5;
notes[419].pitch = B;
notes[419].beats = B1_4;

notes[420].octave = 6;
notes[420].pitch = C;
notes[420].beats = B1_4;

notes[421].octave = 6;
notes[421].pitch = D;
notes[421].beats = B1_4;

notes[422].octave = 6;
notes[422].pitch = E;
notes[422].beats = B1_4;

notes[423].octave = 5;
notes[423].pitch = B;
notes[423].beats = B1_4;

notes[424].octave = 6;
notes[424].pitch = C;
notes[424].beats = B1_4;

notes[425].octave = 6;
notes[425].pitch = D;
notes[425].beats = B1_4;

notes[426].octave = 6;
notes[426].pitch = E;
notes[426].beats = B1_4;

notes[427].octave = 5;
notes[427].pitch = B;
notes[427].beats = B1_4;

notes[428].octave = 6;
notes[428].pitch = C;
notes[428].beats = B1_4;

notes[429].octave = 6;
notes[429].pitch = D;
notes[429].beats = B1_4;

notes[430].octave = 6;
notes[430].pitch = E;
notes[430].beats = B1_4;

notes[431].octave = 6;
notes[431].pitch = D;
notes[431].beats = B1_4;

notes[432].octave = 6;
notes[432].pitch = C;
notes[432].beats = B1_4;

notes[433].octave = 5;
notes[433].pitch = B;
notes[433].beats = B1_4;

notes[434].octave = 6;
notes[434].pitch = C;
notes[434].beats = B1_4;

notes[435].octave = 6;
notes[435].pitch = D;
notes[435].beats = B1_4;

notes[436].octave = 6;
notes[436].pitch = E;
notes[436].beats = B1_4;

notes[437].octave = 6;
notes[437].pitch = F;
notes[437].beats = B1_4;

notes[438].octave = 6;
notes[438].pitch = E;
notes[438].beats = B1_4;

notes[439].octave = 6;
notes[439].pitch = D;
notes[439].beats = B1_4;

notes[440].octave = 6;
notes[440].pitch = E;
notes[440].beats = B1_4;

notes[441].octave = 6;
notes[441].pitch = C;
notes[441].beats = B1_4;

notes[442].octave = 6;
notes[442].pitch = D;
notes[442].beats = B1_4;

notes[443].octave = 6;
notes[443].pitch = E;
notes[443].beats = B1_4;

notes[444].octave = 6;
notes[444].pitch = F;
notes[444].beats = B1_4;

notes[445].octave = 6;
notes[445].pitch = G;
notes[445].beats = B1_4;

notes[446].octave = 6;
notes[446].pitch = D;
notes[446].beats = B1_4;

notes[447].octave = 6;
notes[447].pitch = E;
notes[447].beats = B1_4;

notes[448].octave = 6;
notes[448].pitch = F;
notes[448].beats = B1_4;

notes[449].octave = 6;
notes[449].pitch = G;
notes[449].beats = B1_4;

notes[450].octave = 6;
notes[450].pitch = A;
notes[450].beats = B1_4;

notes[451].octave = 6;
notes[451].pitch = G;
notes[451].beats = B1_4;

notes[452].octave = 6;
notes[452].pitch = F;
notes[452].beats = B1_4;

notes[453].octave = 6;
notes[453].pitch = E;
notes[453].beats = B1_4;

notes[454].octave = 6;
notes[454].pitch = F;
notes[454].beats = B1_4;

notes[455].octave = 6;
notes[455].pitch = G;
notes[455].beats = B1_4;

notes[456].octave = 6;
notes[456].pitch = A;
notes[456].beats = B1_4;

notes[457].octave = 6;
notes[457].pitch = B;
notes[457].beats = B1_4;

notes[458].octave = 7;
notes[458].pitch = C;
notes[458].beats = B1_4;

notes[459].octave = 6;
notes[459].pitch = B;
notes[459].beats = B1_4;

notes[460].octave = 6;
notes[460].pitch = A;
notes[460].beats = B1_4;

notes[461].octave = 6;
notes[461].pitch = B;
notes[461].beats = B1_4;

notes[462].octave = 6;
notes[462].pitch = G;
notes[462].beats = B1_4;

notes[463].octave = 6;
notes[463].pitch = A;
notes[463].beats = B1_4;

notes[464].octave = 6;
notes[464].pitch = B;
notes[464].beats = B1_4;

notes[465].octave = 6;
notes[465].pitch = E;
notes[465].beats = B1_4;

notes[466].octave = 6;
notes[466].pitch = B;
notes[466].beats = B1_4;

notes[467].octave = 6;
notes[467].pitch = G;
notes[467].beats = B1_4;

notes[468].octave = 6;
notes[468].pitch = A;
notes[468].beats = B1_4;

notes[469].octave = 6;
notes[469].pitch = G;
notes[469].beats = B1_4;

notes[470].octave = 6;
notes[470].pitch = A;
notes[470].beats = B1_4;

notes[471].octave = 6;
notes[471].pitch = B;
notes[471].beats = B1_4;

notes[472].octave = 7;
notes[472].pitch = D;
notes[472].beats = B1_4;

notes[473].octave = 6;
notes[473].pitch = E;
notes[473].beats = B1_4;

notes[474].octave = 6;
notes[474].pitch = G;
notes[474].beats = B1_4;

notes[475].octave = 6;
notes[475].pitch = A;
notes[475].beats = B1_4;

notes[476].octave = 6;
notes[476].pitch = B;
notes[476].beats = B1_4;

notes[477].octave = 6;
notes[477].pitch = G;
notes[477].beats = B1_4;

notes[478].octave = 6;
notes[478].pitch = A;
notes[478].beats = B1_4;

notes[479].octave = 6;
notes[479].pitch = B;
notes[479].beats = B1_4;

notes[480].octave = 7;
notes[480].pitch = D;
notes[480].beats = B1_4;

notes[481].octave = 6;
notes[481].pitch = E;
notes[481].beats = B1_4;

notes[482].octave = 7;
notes[482].pitch = C;
notes[482].beats = B1_4;

notes[483].octave = 6;
notes[483].pitch = B;
notes[483].beats = B1_4;

notes[484].octave = 7;
notes[484].pitch = C;
notes[484].beats = B1_4;

notes[485].octave = 6;
notes[485].pitch = A;
notes[485].beats = B1_4;

notes[486].octave = 6;
notes[486].pitch = B;
notes[486].beats = B1_4;

notes[487].octave = 7;
notes[487].pitch = C;
notes[487].beats = B1_4;

notes[488].octave = 7;
notes[488].pitch = D;
notes[488].beats = B1_4;

notes[489].octave = 6;
notes[489].pitch = A;
notes[489].beats = B1_4;

notes[490].octave = 7;
notes[490].pitch = C;
notes[490].beats = B1_4;

notes[491].octave = 6;
notes[491].pitch = B;
notes[491].beats = B1_4;

notes[492].octave = 7;
notes[492].pitch = C;
notes[492].beats = B1_4;

notes[493].octave = 6;
notes[493].pitch = A;
notes[493].beats = B1_4;

notes[494].octave = 6;
notes[494].pitch = B;
notes[494].beats = B1_4;

notes[495].octave = 7;
notes[495].pitch = C;
notes[495].beats = B1_4;

notes[496].octave = 7;
notes[496].pitch = D;
notes[496].beats = B1_4;

notes[497].octave = 6;
notes[497].pitch = A;
notes[497].beats = B1_4;

notes[498].octave = 7;
notes[498].pitch = C;
notes[498].beats = B1_4;

notes[499].octave = 6;
notes[499].pitch = B;
notes[499].beats = B1_4;

notes[500].octave = 7;
notes[500].pitch = C;
notes[500].beats = B1_4;

notes[501].octave = 6;
notes[501].pitch = A;
notes[501].beats = B1_4;

notes[502].octave = 6;
notes[502].pitch = E;
notes[502].beats = B1_4;

notes[503].octave = 7;
notes[503].pitch = C;
notes[503].beats = B1_4;

notes[504].octave = 6;
notes[504].pitch = B;
notes[504].beats = B1_4;

notes[505].octave = 7;
notes[505].pitch = C;
notes[505].beats = B1_4;

notes[506].octave = 6;
notes[506].pitch = A;
notes[506].beats = B1_4;

notes[507].octave = 6;
notes[507].pitch = B;
notes[507].beats = B1_4;

notes[508].octave = 7;
notes[508].pitch = C;
notes[508].beats = B1_4;

notes[509].octave = 7;
notes[509].pitch = D;
notes[509].beats = B1_4;

notes[510].octave = 7;
notes[510].pitch = C;
notes[510].beats = B1_4;

notes[511].octave = 6;
notes[511].pitch = B;
notes[511].beats = B1_4;

notes[512].octave = 7;
notes[512].pitch = C;
notes[512].beats = B1_4;

notes[513].octave = 7;
notes[513].pitch = D;
notes[513].beats = B1_4;

notes[514].octave = 7;
notes[514].pitch = E;
notes[514].beats = B1_4;

notes[515].octave = 6;
notes[515].pitch = B;
notes[515].beats = B1_4;

notes[516].octave = 7;
notes[516].pitch = C;
notes[516].beats = B1_4;

notes[517].octave = 7;
notes[517].pitch = D;
notes[517].beats = B1_4;

notes[518].octave = 7;
notes[518].pitch = E;
notes[518].beats = B1_4;

notes[519].octave = 6;
notes[519].pitch = B;
notes[519].beats = B1_4;

notes[520].octave = 7;
notes[520].pitch = C;
notes[520].beats = B1_4;

notes[521].octave = 7;
notes[521].pitch = D;
notes[521].beats = B1_4;

notes[522].octave = 7;
notes[522].pitch = E;
notes[522].beats = B1_4;

notes[523].octave = 6;
notes[523].pitch = B;
notes[523].beats = B1_4;

notes[524].octave = 7;
notes[524].pitch = C;
notes[524].beats = B1_4;

notes[525].octave = 7;
notes[525].pitch = D;
notes[525].beats = B1_4;

notes[526].octave = 7;
notes[526].pitch = E;
notes[526].beats = B1_4;

notes[527].octave = 6;
notes[527].pitch = B;
notes[527].beats = B1_4;

notes[528].octave = 7;
notes[528].pitch = C;
notes[528].beats = B1_4;

notes[529].octave = 7;
notes[529].pitch = D;
notes[529].beats = B1_4;

notes[530].octave = 7;
notes[530].pitch = E;
notes[530].beats = B3;

notes[531].octave = 7;
notes[531].pitch = E;
notes[531].beats = B3;

notes[532].octave = 4;
notes[532].pitch = A;
notes[532].beats = B1_4;

notes[533].octave = 4;
notes[533].pitch = F;
notes[533].beats = B1_4;

notes[534].octave = 4;
notes[534].pitch = E;
notes[534].beats = B1_4;

notes[535].octave = 4;
notes[535].pitch = C;
notes[535].beats = B1_4;

notes[536].octave = 5;
notes[536].pitch = E;
notes[536].beats = B1_4;

notes[537].octave = 4;
notes[537].pitch = C;
notes[537].beats = B1_4;

notes[538].octave = 4;
notes[538].pitch = E;
notes[538].beats = B1_4;

notes[539].octave = 4;
notes[539].pitch = F;
notes[539].beats = B1_4;

notes[540].octave = 4;
notes[540].pitch = A;
notes[540].beats = B1_4;

notes[541].octave = 4;
notes[541].pitch = F;
notes[541].beats = B1_4;

notes[542].octave = 4;
notes[542].pitch = E;
notes[542].beats = B1_4;

notes[543].octave = 4;
notes[543].pitch = C;
notes[543].beats = B1_4;

notes[544].octave = 4;
notes[544].pitch = A;
notes[544].beats = B1_4;

notes[545].octave = 4;
notes[545].pitch = F;
notes[545].beats = B1_4;

notes[546].octave = 4;
notes[546].pitch = E;
notes[546].beats = B1_4;

notes[547].octave = 4;
notes[547].pitch = C;
notes[547].beats = B1_4;

notes[548].octave = 5;
notes[548].pitch = E;
notes[548].beats = B1_4;

notes[549].octave = 4;
notes[549].pitch = C;
notes[549].beats = B1_4;

notes[550].octave = 4;
notes[550].pitch = E;
notes[550].beats = B1_4;

notes[551].octave = 4;
notes[551].pitch = F;
notes[551].beats = B1_4;

notes[552].octave = 4;
notes[552].pitch = A;
notes[552].beats = B1_4;

notes[553].octave = 4;
notes[553].pitch = F;
notes[553].beats = B1_4;

notes[554].octave = 4;
notes[554].pitch = E;
notes[554].beats = B1_4;

notes[555].octave = 4;
notes[555].pitch = C;
notes[555].beats = B1_4;

notes[556].octave = 4;
notes[556].pitch = B;
notes[556].beats = B1_4;

notes[557].octave = 4;
notes[557].pitch = G;
notes[557].beats = B1_4;

notes[558].octave = 4;
notes[558].pitch = E;
notes[558].beats = B1_4;

notes[559].octave = 4;
notes[559].pitch = D;
notes[559].beats = B1_4;

notes[560].octave = 5;
notes[560].pitch = E;
notes[560].beats = B1_4;

notes[561].octave = 4;
notes[561].pitch = D;
notes[561].beats = B1_4;

notes[562].octave = 4;
notes[562].pitch = E;
notes[562].beats = B1_4;

notes[563].octave = 4;
notes[563].pitch = G;
notes[563].beats = B1_4;

notes[564].octave = 4;
notes[564].pitch = B;
notes[564].beats = B1_4;

notes[565].octave = 4;
notes[565].pitch = G;
notes[565].beats = B1_4;

notes[566].octave = 4;
notes[566].pitch = E;
notes[566].beats = B1_4;

notes[567].octave = 4;
notes[567].pitch = D;
notes[567].beats = B1_4;

notes[568].octave = 4;
notes[568].pitch = B;
notes[568].beats = B1_4;

notes[569].octave = 4;
notes[569].pitch = G;
notes[569].beats = B1_4;

notes[570].octave = 4;
notes[570].pitch = E;
notes[570].beats = B1_4;

notes[571].octave = 4;
notes[571].pitch = D;
notes[571].beats = B1_4;

notes[572].octave = 5;
notes[572].pitch = E;
notes[572].beats = B1_4;

notes[573].octave = 4;
notes[573].pitch = D;
notes[573].beats = B1_4;

notes[574].octave = 4;
notes[574].pitch = E;
notes[574].beats = B1_4;

notes[575].octave = 4;
notes[575].pitch = G;
notes[575].beats = B1_4;

notes[576].octave = 4;
notes[576].pitch = B;
notes[576].beats = B1_4;

notes[577].octave = 4;
notes[577].pitch = G;
notes[577].beats = B1_4;

notes[578].octave = 4;
notes[578].pitch = E;
notes[578].beats = B1_4;

notes[579].octave = 4;
notes[579].pitch = D;
notes[579].beats = B1_4;

notes[580].octave = 5;
notes[580].pitch = C;
notes[580].beats = B1_4;

notes[581].octave = 4;
notes[581].pitch = A;
notes[581].beats = B1_4;

notes[582].octave = 4;
notes[582].pitch = E;
notes[582].beats = B1_4;

notes[583].octave = 4;
notes[583].pitch = C;
notes[583].beats = B1_4;

notes[584].octave = 5;
notes[584].pitch = E;
notes[584].beats = B1_4;

notes[585].octave = 4;
notes[585].pitch = C;
notes[585].beats = B1_4;

notes[586].octave = 4;
notes[586].pitch = E;
notes[586].beats = B1_4;

notes[587].octave = 4;
notes[587].pitch = A;
notes[587].beats = B1_4;

notes[588].octave = 5;
notes[588].pitch = C;
notes[588].beats = B1_4;

notes[589].octave = 4;
notes[589].pitch = A;
notes[589].beats = B1_4;

notes[590].octave = 4;
notes[590].pitch = E;
notes[590].beats = B1_4;

notes[591].octave = 4;
notes[591].pitch = C;
notes[591].beats = B1_4;

notes[592].octave = 5;
notes[592].pitch = C;
notes[592].beats = B1_4;

notes[593].octave = 4;
notes[593].pitch = A;
notes[593].beats = B1_4;

notes[594].octave = 4;
notes[594].pitch = E;
notes[594].beats = B1_4;

notes[595].octave = 4;
notes[595].pitch = C;
notes[595].beats = B1_4;

notes[596].octave = 5;
notes[596].pitch = E;
notes[596].beats = B1_4;

notes[597].octave = 4;
notes[597].pitch = C;
notes[597].beats = B1_4;

notes[598].octave = 4;
notes[598].pitch = E;
notes[598].beats = B1_4;

notes[599].octave = 4;
notes[599].pitch = A;
notes[599].beats = B1_4;

notes[600].octave = 5;
notes[600].pitch = C;
notes[600].beats = B1_4;

notes[601].octave = 4;
notes[601].pitch = A;
notes[601].beats = B1_4;

notes[602].octave = 4;
notes[602].pitch = E;
notes[602].beats = B1_4;

notes[603].octave = 4;
notes[603].pitch = C;
notes[603].beats = B1_4;

notes[604].octave = 4;
notes[604].pitch = B;
notes[604].beats = B1_4;

notes[605].octave = 4;
notes[605].pitch = G;
notes[605].beats = B1_4;

notes[606].octave = 4;
notes[606].pitch = E;
notes[606].beats = B1_4;

notes[607].octave = 4;
notes[607].pitch = D;
notes[607].beats = B1_4;

notes[608].octave = 5;
notes[608].pitch = E;
notes[608].beats = B1_4;

notes[609].octave = 4;
notes[609].pitch = D;
notes[609].beats = B1_4;

notes[610].octave = 4;
notes[610].pitch = E;
notes[610].beats = B1_4;

notes[611].octave = 4;
notes[611].pitch = G;
notes[611].beats = B1_4;

notes[612].octave = 4;
notes[612].pitch = B;
notes[612].beats = B1_4;

notes[613].octave = 4;
notes[613].pitch = G;
notes[613].beats = B1_4;

notes[614].octave = 4;
notes[614].pitch = E;
notes[614].beats = B1_4;

notes[615].octave = 4;
notes[615].pitch = D;
notes[615].beats = B1_4;

notes[616].octave = 4;
notes[616].pitch = B;
notes[616].beats = B1_4;

notes[617].octave = 4;
notes[617].pitch = G;
notes[617].beats = B1_4;

notes[618].octave = 4;
notes[618].pitch = E;
notes[618].beats = B1_4;

notes[619].octave = 4;
notes[619].pitch = D;
notes[619].beats = B1_4;

notes[620].octave = 5;
notes[620].pitch = E;
notes[620].beats = B1_4;

notes[621].octave = 4;
notes[621].pitch = D;
notes[621].beats = B1_4;

notes[622].octave = 4;
notes[622].pitch = E;
notes[622].beats = B1_4;

notes[623].octave = 4;
notes[623].pitch = G;
notes[623].beats = B1_4;

notes[624].octave = 4;
notes[624].pitch = B;
notes[624].beats = B1_4;

notes[625].octave = 4;
notes[625].pitch = G;
notes[625].beats = B1_4;

notes[626].octave = 4;
notes[626].pitch = E;
notes[626].beats = B1_4;

notes[627].octave = 4;
notes[627].pitch = D;
notes[627].beats = B1_4;

notes[628].octave = 4;
notes[628].pitch = A;
notes[628].beats = B1_4;

notes[629].octave = 4;
notes[629].pitch = F;
notes[629].beats = B1_4;

notes[630].octave = 4;
notes[630].pitch = E;
notes[630].beats = B1_4;

notes[631].octave = 4;
notes[631].pitch = C;
notes[631].beats = B1_4;

notes[632].octave = 5;
notes[632].pitch = E;
notes[632].beats = B1_4;

notes[633].octave = 4;
notes[633].pitch = C;
notes[633].beats = B1_4;

notes[634].octave = 4;
notes[634].pitch = E;
notes[634].beats = B1_4;

notes[635].octave = 4;
notes[635].pitch = F;
notes[635].beats = B1_4;

notes[636].octave = 4;
notes[636].pitch = A;
notes[636].beats = B1_4;

notes[637].octave = 4;
notes[637].pitch = F;
notes[637].beats = B1_4;

notes[638].octave = 4;
notes[638].pitch = E;
notes[638].beats = B1_4;

notes[639].octave = 4;
notes[639].pitch = C;
notes[639].beats = B1_4;

notes[640].octave = 4;
notes[640].pitch = A;
notes[640].beats = B1_4;

notes[641].octave = 4;
notes[641].pitch = F;
notes[641].beats = B1_4;

notes[642].octave = 4;
notes[642].pitch = E;
notes[642].beats = B1_4;

notes[643].octave = 4;
notes[643].pitch = C;
notes[643].beats = B1_4;

notes[644].octave = 5;
notes[644].pitch = E;
notes[644].beats = B1_4;

notes[645].octave = 4;
notes[645].pitch = C;
notes[645].beats = B1_4;

notes[646].octave = 4;
notes[646].pitch = E;
notes[646].beats = B1_4;

notes[647].octave = 4;
notes[647].pitch = F;
notes[647].beats = B1_4;

notes[648].octave = 4;
notes[648].pitch = A;
notes[648].beats = B1_4;

notes[649].octave = 4;
notes[649].pitch = F;
notes[649].beats = B1_4;

notes[650].octave = 4;
notes[650].pitch = E;
notes[650].beats = B1_4;

notes[651].octave = 4;
notes[651].pitch = C;
notes[651].beats = B1_4;

notes[652].octave = 5;
notes[652].pitch = B;
notes[652].beats = B1_4;

notes[653].octave = 5;
notes[653].pitch = G;
notes[653].beats = B1_4;

notes[654].octave = 5;
notes[654].pitch = E;
notes[654].beats = B1_4;

notes[655].octave = 5;
notes[655].pitch = D;
notes[655].beats = B1_4;

notes[656].octave = 6;
notes[656].pitch = E;
notes[656].beats = B1_4;

notes[657].octave = 5;
notes[657].pitch = D;
notes[657].beats = B1_4;

notes[658].octave = 5;
notes[658].pitch = E;
notes[658].beats = B1_4;

notes[659].octave = 5;
notes[659].pitch = G;
notes[659].beats = B1_4;

notes[660].octave = 5;
notes[660].pitch = B;
notes[660].beats = B1_4;

notes[661].octave = 5;
notes[661].pitch = G;
notes[661].beats = B1_4;

notes[662].octave = 5;
notes[662].pitch = E;
notes[662].beats = B1_4;

notes[663].octave = 5;
notes[663].pitch = D;
notes[663].beats = B1_4;

notes[664].octave = 5;
notes[664].pitch = B;
notes[664].beats = B1_4;

notes[665].octave = 5;
notes[665].pitch = G;
notes[665].beats = B1_4;

notes[666].octave = 5;
notes[666].pitch = E;
notes[666].beats = B1_4;

notes[667].octave = 5;
notes[667].pitch = D;
notes[667].beats = B1_4;

notes[668].octave = 6;
notes[668].pitch = E;
notes[668].beats = B1_4;

notes[669].octave = 5;
notes[669].pitch = D;
notes[669].beats = B1_4;

notes[670].octave = 5;
notes[670].pitch = E;
notes[670].beats = B1_4;

notes[671].octave = 5;
notes[671].pitch = G;
notes[671].beats = B1_4;

notes[672].octave = 5;
notes[672].pitch = B;
notes[672].beats = B1_4;

notes[673].octave = 5;
notes[673].pitch = G;
notes[673].beats = B1_4;

notes[674].octave = 5;
notes[674].pitch = E;
notes[674].beats = B1_4;

notes[675].octave = 5;
notes[675].pitch = D;
notes[675].beats = B1_4;

notes[676].octave = 6;
notes[676].pitch = C;
notes[676].beats = B1_4;

notes[677].octave = 5;
notes[677].pitch = A;
notes[677].beats = B1_4;

notes[678].octave = 5;
notes[678].pitch = E;
notes[678].beats = B1_4;

notes[679].octave = 5;
notes[679].pitch = C;
notes[679].beats = B1_4;

notes[680].octave = 6;
notes[680].pitch = E;
notes[680].beats = B1_4;

notes[681].octave = 5;
notes[681].pitch = C;
notes[681].beats = B1_4;

notes[682].octave = 5;
notes[682].pitch = E;
notes[682].beats = B1_4;

notes[683].octave = 5;
notes[683].pitch = A;
notes[683].beats = B1_4;

notes[684].octave = 6;
notes[684].pitch = C;
notes[684].beats = B1_4;

notes[685].octave = 5;
notes[685].pitch = A;
notes[685].beats = B1_4;

notes[686].octave = 5;
notes[686].pitch = E;
notes[686].beats = B1_4;

notes[687].octave = 5;
notes[687].pitch = C;
notes[687].beats = B1_4;

notes[688].octave = 6;
notes[688].pitch = C;
notes[688].beats = B1_4;

notes[689].octave = 5;
notes[689].pitch = A;
notes[689].beats = B1_4;

notes[690].octave = 5;
notes[690].pitch = E;
notes[690].beats = B1_4;

notes[691].octave = 5;
notes[691].pitch = C;
notes[691].beats = B1_4;

notes[692].octave = 6;
notes[692].pitch = E;
notes[692].beats = B1_4;

notes[693].octave = 5;
notes[693].pitch = C;
notes[693].beats = B1_4;

notes[694].octave = 5;
notes[694].pitch = E;
notes[694].beats = B1_4;

notes[695].octave = 5;
notes[695].pitch = A;
notes[695].beats = B1_4;

notes[696].octave = 6;
notes[696].pitch = C;
notes[696].beats = B1_4;

notes[697].octave = 5;
notes[697].pitch = A;
notes[697].beats = B1_4;

notes[698].octave = 5;
notes[698].pitch = E;
notes[698].beats = B1_4;

notes[699].octave = 5;
notes[699].pitch = C;
notes[699].beats = B1_4;

notes[700].octave = 5;
notes[700].pitch = B;
notes[700].beats = B1_4;

notes[701].octave = 5;
notes[701].pitch = G;
notes[701].beats = B1_4;

notes[702].octave = 5;
notes[702].pitch = E;
notes[702].beats = B1_4;

notes[703].octave = 5;
notes[703].pitch = D;
notes[703].beats = B1_4;

notes[704].octave = 6;
notes[704].pitch = E;
notes[704].beats = B1_4;

notes[705].octave = 5;
notes[705].pitch = D;
notes[705].beats = B1_4;

notes[706].octave = 5;
notes[706].pitch = E;
notes[706].beats = B1_4;

notes[707].octave = 5;
notes[707].pitch = G;
notes[707].beats = B1_4;

notes[708].octave = 5;
notes[708].pitch = B;
notes[708].beats = B1_4;

notes[709].octave = 5;
notes[709].pitch = G;
notes[709].beats = B1_4;

notes[710].octave = 5;
notes[710].pitch = E;
notes[710].beats = B1_4;

notes[711].octave = 5;
notes[711].pitch = D;
notes[711].beats = B1_4;

notes[712].octave = 5;
notes[712].pitch = B;
notes[712].beats = B1_4;

notes[713].octave = 5;
notes[713].pitch = G;
notes[713].beats = B1_4;

notes[714].octave = 5;
notes[714].pitch = E;
notes[714].beats = B1_4;

notes[715].octave = 5;
notes[715].pitch = D;
notes[715].beats = B1_4;

notes[716].octave = 6;
notes[716].pitch = E;
notes[716].beats = B1_4;

notes[717].octave = 5;
notes[717].pitch = D;
notes[717].beats = B1_4;

notes[718].octave = 5;
notes[718].pitch = E;
notes[718].beats = B1_4;

notes[719].octave = 5;
notes[719].pitch = G;
notes[719].beats = B1_4;

notes[720].octave = 5;
notes[720].pitch = B;
notes[720].beats = B1_4;

notes[721].octave = 5;
notes[721].pitch = G;
notes[721].beats = B1_4;

notes[722].octave = 5;
notes[722].pitch = E;
notes[722].beats = B1_4;

notes[723].octave = 5;
notes[723].pitch = D;
notes[723].beats = B1_4;

notes[724].octave = 6;
notes[724].pitch = A;
notes[724].beats = B1_4;

notes[725].octave = 6;
notes[725].pitch = F;
notes[725].beats = B1_4;

notes[726].octave = 6;
notes[726].pitch = E;
notes[726].beats = B1_4;

notes[727].octave = 6;
notes[727].pitch = C;
notes[727].beats = B1_4;

notes[728].octave = 7;
notes[728].pitch = E;
notes[728].beats = B1_4;

notes[729].octave = 6;
notes[729].pitch = C;
notes[729].beats = B1_4;

notes[730].octave = 6;
notes[730].pitch = E;
notes[730].beats = B1_4;

notes[731].octave = 6;
notes[731].pitch = F;
notes[731].beats = B1_4;

notes[732].octave = 6;
notes[732].pitch = A;
notes[732].beats = B1_4;

notes[733].octave = 6;
notes[733].pitch = F;
notes[733].beats = B1_4;

notes[734].octave = 6;
notes[734].pitch = E;
notes[734].beats = B1_4;

notes[735].octave = 6;
notes[735].pitch = C;
notes[735].beats = B1_4;

notes[736].octave = 6;
notes[736].pitch = A;
notes[736].beats = B1_4;

notes[737].octave = 6;
notes[737].pitch = F;
notes[737].beats = B1_4;

notes[738].octave = 6;
notes[738].pitch = E;
notes[738].beats = B1_4;

notes[739].octave = 6;
notes[739].pitch = C;
notes[739].beats = B1_4;

notes[740].octave = 7;
notes[740].pitch = E;
notes[740].beats = B1_4;

notes[741].octave = 6;
notes[741].pitch = C;
notes[741].beats = B1_4;

notes[742].octave = 6;
notes[742].pitch = E;
notes[742].beats = B1_4;

notes[743].octave = 6;
notes[743].pitch = F;
notes[743].beats = B1_4;

notes[744].octave = 6;
notes[744].pitch = A;
notes[744].beats = B1_4;

notes[745].octave = 6;
notes[745].pitch = F;
notes[745].beats = B1_4;

notes[746].octave = 6;
notes[746].pitch = E;
notes[746].beats = B1_4;

notes[747].octave = 6;
notes[747].pitch = C;
notes[747].beats = B1_4;

notes[748].octave = 6;
notes[748].pitch = B;
notes[748].beats = B1_4;

notes[749].octave = 6;
notes[749].pitch = G;
notes[749].beats = B1_4;

notes[750].octave = 6;
notes[750].pitch = E;
notes[750].beats = B1_4;

notes[751].octave = 6;
notes[751].pitch = D;
notes[751].beats = B1_4;

notes[752].octave = 7;
notes[752].pitch = E;
notes[752].beats = B1_4;

notes[753].octave = 6;
notes[753].pitch = D;
notes[753].beats = B1_4;

notes[754].octave = 6;
notes[754].pitch = E;
notes[754].beats = B1_4;

notes[755].octave = 6;
notes[755].pitch = G;
notes[755].beats = B1_4;

notes[756].octave = 6;
notes[756].pitch = B;
notes[756].beats = B1_4;

notes[757].octave = 6;
notes[757].pitch = G;
notes[757].beats = B1_4;

notes[758].octave = 6;
notes[758].pitch = E;
notes[758].beats = B1_4;

notes[759].octave = 6;
notes[759].pitch = D;
notes[759].beats = B1_4;

notes[760].octave = 6;
notes[760].pitch = B;
notes[760].beats = B1_4;

notes[761].octave = 6;
notes[761].pitch = G;
notes[761].beats = B1_4;

notes[762].octave = 6;
notes[762].pitch = E;
notes[762].beats = B1_4;

notes[763].octave = 6;
notes[763].pitch = D;
notes[763].beats = B1_4;

notes[764].octave = 7;
notes[764].pitch = E;
notes[764].beats = B1_4;

notes[765].octave = 6;
notes[765].pitch = D;
notes[765].beats = B1_4;

notes[766].octave = 6;
notes[766].pitch = E;
notes[766].beats = B1_4;

notes[767].octave = 6;
notes[767].pitch = G;
notes[767].beats = B1_4;

notes[768].octave = 6;
notes[768].pitch = B;
notes[768].beats = B1_4;

notes[769].octave = 6;
notes[769].pitch = G;
notes[769].beats = B1_4;

notes[770].octave = 6;
notes[770].pitch = E;
notes[770].beats = B1_4;

notes[771].octave = 6;
notes[771].pitch = D;
notes[771].beats = B1_4;

notes[772].octave = 7;
notes[772].pitch = C;
notes[772].beats = B1_4;

notes[773].octave = 6;
notes[773].pitch = A;
notes[773].beats = B1_4;

notes[774].octave = 6;
notes[774].pitch = E;
notes[774].beats = B1_4;

notes[775].octave = 6;
notes[775].pitch = C;
notes[775].beats = B1_4;

notes[776].octave = 7;
notes[776].pitch = E;
notes[776].beats = B1_4;

notes[777].octave = 6;
notes[777].pitch = C;
notes[777].beats = B1_4;

notes[778].octave = 6;
notes[778].pitch = E;
notes[778].beats = B1_4;

notes[779].octave = 6;
notes[779].pitch = A;
notes[779].beats = B1_4;

notes[780].octave = 7;
notes[780].pitch = C;
notes[780].beats = B1_4;

notes[781].octave = 6;
notes[781].pitch = A;
notes[781].beats = B1_4;

notes[782].octave = 6;
notes[782].pitch = E;
notes[782].beats = B1_4;

notes[783].octave = 6;
notes[783].pitch = C;
notes[783].beats = B1_4;

notes[784].octave = 7;
notes[784].pitch = C;
notes[784].beats = B1_4;

notes[785].octave = 6;
notes[785].pitch = A;
notes[785].beats = B1_4;

notes[786].octave = 6;
notes[786].pitch = E;
notes[786].beats = B1_4;

notes[787].octave = 6;
notes[787].pitch = C;
notes[787].beats = B1_4;

notes[788].octave = 7;
notes[788].pitch = E;
notes[788].beats = B1_4;

notes[789].octave = 6;
notes[789].pitch = C;
notes[789].beats = B1_4;

notes[790].octave = 6;
notes[790].pitch = E;
notes[790].beats = B1_4;

notes[791].octave = 6;
notes[791].pitch = A;
notes[791].beats = B1_4;

notes[792].octave = 7;
notes[792].pitch = C;
notes[792].beats = B1_4;

notes[793].octave = 6;
notes[793].pitch = A;
notes[793].beats = B1_4;

notes[794].octave = 6;
notes[794].pitch = E;
notes[794].beats = B1_4;

notes[795].octave = 6;
notes[795].pitch = C;
notes[795].beats = B1_4;

notes[796].octave = 6;
notes[796].pitch = B;
notes[796].beats = B1_4;

notes[797].octave = 6;
notes[797].pitch = G;
notes[797].beats = B1_4;

notes[798].octave = 6;
notes[798].pitch = E;
notes[798].beats = B1_4;

notes[799].octave = 6;
notes[799].pitch = D;
notes[799].beats = B1_4;

notes[800].octave = 7;
notes[800].pitch = E;
notes[800].beats = B1_4;

notes[801].octave = 6;
notes[801].pitch = D;
notes[801].beats = B1_4;

notes[802].octave = 6;
notes[802].pitch = E;
notes[802].beats = B1_4;

notes[803].octave = 6;
notes[803].pitch = G;
notes[803].beats = B1_4;

notes[804].octave = 6;
notes[804].pitch = B;
notes[804].beats = B1_4;

notes[805].octave = 6;
notes[805].pitch = G;
notes[805].beats = B1_4;

notes[806].octave = 6;
notes[806].pitch = E;
notes[806].beats = B1_4;

notes[807].octave = 6;
notes[807].pitch = D;
notes[807].beats = B1_4;

notes[808].octave = 6;
notes[808].pitch = B;
notes[808].beats = B1_4;

notes[809].octave = 6;
notes[809].pitch = G;
notes[809].beats = B1_4;

notes[810].octave = 6;
notes[810].pitch = E;
notes[810].beats = B1_4;

notes[811].octave = 6;
notes[811].pitch = D;
notes[811].beats = B1_4;

notes[812].octave = 7;
notes[812].pitch = E;
notes[812].beats = B1_4;

notes[813].octave = 6;
notes[813].pitch = D;
notes[813].beats = B1_4;

notes[814].octave = 6;
notes[814].pitch = E;
notes[814].beats = B1_4;

notes[815].octave = 6;
notes[815].pitch = G;
notes[815].beats = B1_4;

notes[816].octave = 6;
notes[816].pitch = B;
notes[816].beats = B1_4;

notes[817].octave = 6;
notes[817].pitch = G;
notes[817].beats = B1_4;

notes[818].octave = 6;
notes[818].pitch = E;
notes[818].beats = B1_4;

notes[819].octave = 6;
notes[819].pitch = D;
notes[819].beats = B1_4;

notes[820].octave = 4;
notes[820].pitch = E;
notes[820].beats = B1;

notes[821].octave = 5;
notes[821].pitch = E;
notes[821].beats = B1;

notes[822].octave = 5;
notes[822].pitch = E;
notes[822].beats = B1;

notes[823].octave = 5;
notes[823].pitch = E;
notes[823].beats = B1;

notes[824].octave = 5;
notes[824].pitch = E;
notes[824].beats = B1;

notes[825].octave = 5;
notes[825].pitch = E;
notes[825].beats = B1;

notes[826].octave = 5;
notes[826].pitch = E;
notes[826].beats = B1;

notes[827].octave = 5;
notes[827].pitch = E;
notes[827].beats = B1;

notes[828].octave = 5;
notes[828].pitch = E;
notes[828].beats = B1;

notes[829].octave = 5;
notes[829].pitch = E;
notes[829].beats = B1;

notes[830].octave = 5;
notes[830].pitch = E;
notes[830].beats = B1;

notes[831].octave = 5;
notes[831].pitch = E;
notes[831].beats = B1;
 
   // redButton = digitalRead(redPin);
    //yellowButton = digitalRead(yellowPin);
    //greenButton = digitalRead(greenPin);
    blueButton = digitalRead(bluePin);
    //lcd.clear();


    /*if(greenButton == LOW && blueButton == LOW){
        //lcd.print("Believer");
        //play(believer_notes, believer_beats, BelieverLength, 260);
        digitalWrite(13, HIGH);
    }
    else if(redButton == LOW && yellowButton == LOW){
        //lcd.print("Lights Down Low");
        //play(lightsDownLow_notes, lightsDownLow_beats, lightsDownLowLength, 700);
    }
      if(redButton == LOW){
        //lcd.print("Star Wars");
        //lcd.setCursor(0,1);
        //lcd.print("Theme Song");
        digitalWrite(9, HIGH);
        //play(starWars_notes, starWars_beats, StarWarsLength, 400);
    }
    else if(yellowButton == LOW){
        //lcd.print("Imperial March");
        digitalWrite(13, HIGH);
        //play(imperialMarch_notes, imperialMarch_beats, imperialMarchLength, 560);
    }
    else if(greenButton == LOW){
        //lcd.print("Let it Go");
        digitalWrite(7, HIGH);
        //play(letItGo_notes, letItGo_beats, letItGoLength, 360);
    }*/
    if(blueButton == LOW){
        //lcd.print("iSpy");
        digitalWrite(11, HIGH);
        play(InterstellarLength);
    }
      

    }




