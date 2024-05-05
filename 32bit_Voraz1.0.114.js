function getClassLoader() {

    const classLoader = {

        Gravity: Java.use("android.view.Gravity"),

        TextView: Java.use("android.widget.TextView"),

        LinearLayout: Java.use("android.widget.LinearLayout"),

        ViewGroup_LayoutParams: Java.use("android.view.ViewGroup$LayoutParams"),

        LinearLayout_LayoutParams: Java.use("android.widget.LinearLayout$LayoutParams"),

        Color: Java.use("android.graphics.Color"),

        ActivityThread: Java.use("android.app.ActivityThread"),

        ActivityThread_ActivityClientRecord: Java.use("android.app.ActivityThread$ActivityClientRecord"),

        View_OnTouchListener: Java.use("android.view.View$OnTouchListener"),

        MotionEvent: Java.use("android.view.MotionEvent"),

        String: Java.use("java.lang.String"),

        ScrollView: Java.use("android.widget.ScrollView"),

        View_OnClickListener: Java.use("android.view.View$OnClickListener"),

        SeekBar: Java.use("android.widget.SeekBar") // Adicionando defini莽茫o para SeekBar

    }

    return classLoader

}



function pixelDensityToPixels(context, dp) {

    const density = context.getResources().getDisplayMetrics().density.value

    return parseInt(dp * density)

}



function getMainActivity(classLoader) {

    const activityThread = classLoader.ActivityThread.sCurrentActivityThread.value

    const mActivities = activityThread.mActivities.value

    const activityClientRecord = Java.cast(mActivities.valueAt(0), classLoader.ActivityThread_ActivityClientRecord)

    return activityClientRecord.activity.value

}





class Menu {

    #classLoader

    #activity

    #MATCH_PARENT

    #mainLayout

    #menuStart

    #menuLayout

    #menuBarLayout

    #menuBarTitle

    #menuScroll

    #menuOptions

    #options

    #contentView

    #WRAP_CONTENT

    #menuScrollLayout

    #menuScrollView

    #colorOn

    #colorOff





    constructor(classLoader, activity) {

        this.#classLoader = classLoader

        this.#activity = activity

        this.#MATCH_PARENT = classLoader.LinearLayout_LayoutParams.MATCH_PARENT.value

        this.#WRAP_CONTENT = classLoader.LinearLayout_LayoutParams.WRAP_CONTENT.value

        this.#options = {}

        this.#createContentView()

        this.#createMainLayout()

        this.#createMenuScroll()

    }



    #createContentView() {

        this.#contentView = this.#classLoader.LinearLayout.$new(this.#activity)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#MATCH_PARENT)

        this.#contentView.setLayoutParams(layoutParams)

        this.#contentView.setGravity(this.#classLoader.Gravity.CENTER.value)

        this.#contentView.setBackgroundColor(this.#classLoader.Color.TRANSPARENT.value)

    }



    #createMainLayout() {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT)

        this.#mainLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#mainLayout.setLayoutParams(layoutParams)

    }



    #createMenuScroll() {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT)

        this.#menuScrollView = this.#classLoader.ScrollView.$new(this.#activity)

        const padding = pixelDensityToPixels(this.#activity, 8)

        this.#menuScrollView.setLayoutParams(layoutParams)

        this.#menuScrollView.setPadding(padding, padding, padding, padding)

        this.#menuScrollView.mFillViewport.value = true

    }



    #createMenuScrollLayout() {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT)

        this.#menuScrollLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#menuScrollLayout.setLayoutParams(layoutParams)

        this.#menuScrollLayout.setOrientation(this.#menuScrollLayout.VERTICAL.value)

    }



    createMenuOptionsLayout(colorOn, colorOff) {

        this.#createMenuScroll()

        this.#createMenuScrollLayout()

        this.#colorOn = colorOn

        this.#colorOff = colorOff

    }



    createMenuStart(title, size, color) {

        size = pixelDensityToPixels(this.#activity, size)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT)

        this.#menuStart = this.#classLoader.TextView.$new(this.#activity)

        this.#menuStart.setLayoutParams(layoutParams)

        this.#menuStart.setText(this.#classLoader.String.$new(title))

        this.#menuStart.setTextSize(size)

        this.#menuStart.setTextColor(this.#classLoader.Color.parseColor(color))

    }



    createMenuLayout(color, size) {

        const SIZE_DP = pixelDensityToPixels(this.#activity, size)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(SIZE_DP, SIZE_DP)

        this.#menuLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#menuLayout.setLayoutParams(layoutParams)

        this.#menuLayout.setBackgroundColor(this.#classLoader.Color.parseColor(color))

        this.#menuLayout.setOrientation(this.#menuLayout.VERTICAL.value)

    }



    createMenuBarLayout(color) {

        const padding = pixelDensityToPixels(this.#activity, 10)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT)

        this.#menuBarLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#menuBarLayout.setLayoutParams(layoutParams)

        this.#menuBarLayout.setBackgroundColor(this.#classLoader.Color.parseColor(color))

        this.#menuBarLayout.setPadding(padding, padding, 0, padding)

    }



createMenuBarTitle(title, color, size) {
    const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT);
    this.#menuBarTitle = this.#classLoader.TextView.$new(this.#activity);
    this.#menuBarTitle.setLayoutParams(layoutParams);
    this.#menuBarTitle.setText(this.#classLoader.String.$new(title));
    this.#menuBarTitle.setTextColor(this.#classLoader.Color.parseColor(color));
    this.#menuBarTitle.setTextSize(size); // Adiciona o tamanho do texto
}



    #drawContentView() {

        this.#activity.addContentView(this.#contentView, this.#contentView.getLayoutParams())

    }



    #drawMainLayout() {

        this.#contentView.addView(this.#mainLayout)

    }



    #drawMenuStart() {

        this.#mainLayout.addView(this.#menuStart)

    }



    #drawMenuLayout() {

        this.#mainLayout.addView(this.#menuLayout)

    }



    #drawMenuBarLayout() {

        this.#menuLayout.addView(this.#menuBarLayout)

    }



    #drawMenuBarTitle() {

        this.#menuBarLayout.addView(this.#menuBarTitle)

    }



    #drawMenuOptions() {

        this.#menuLayout.addView(this.#menuScrollView)

        this.#menuScrollView.addView(this.#menuScrollLayout)

    }



    #createOptionClickEvent(id, optionView, callbacks) {

        const classLoader = this.#classLoader

        let optionState = false

        const colorOn = this.#colorOn

        const colorOff = this.#colorOff

        const optionOnClickListener = Java.registerClass({

            name: "com.example." + id,

            implements: [classLoader.View_OnClickListener],

            methods: {

                onClick(p1) {

                    if (!optionState) {

                        p1.setBackgroundColor(classLoader.Color.parseColor(colorOn))

                        optionState = true

                        callbacks.on()

                    } else {

                        p1.setBackgroundColor(classLoader.Color.parseColor(colorOff))

                        optionState = false

                        callbacks.off()

                    }

                }

            }

        })

        optionView.setOnClickListener(optionOnClickListener.$new())

    }



    addOption(id, name, callbacks) {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT)

        const padding = pixelDensityToPixels(this.#activity, 5)

        const option = this.#classLoader.TextView.$new(this.#activity)

        const margin = pixelDensityToPixels(this.#activity, 10)

        option.setText(this.#classLoader.String.$new(name))

        option.setBackgroundColor(this.#classLoader.Color.parseColor(this.#colorOff))

        option.setTextColor(this.#classLoader.Color.parseColor("#75757B"))

        layoutParams.setMargins(0, 0, 0, margin)

        option.setLayoutParams(layoutParams)

        option.setPadding(padding, padding, 0, padding)

        this.#menuScrollLayout.addView(option)

        this.#createOptionClickEvent(id, option, callbacks)

    }
    
    
    addTextInput(hint, callback) {
    const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);
    const margin = pixelDensityToPixels(this.#activity, 5);
    
    const editText = this.#classLoader.EditText.$new(this.#activity);
    editText.setHint(this.#classLoader.String.$new(hint));
    editText.setLayoutParams(layoutParams);
    editText.setPadding(0, 0, 0, margin);

    const TextWatcher = Java.use("android.text.TextWatcher");
    const TextWatcherImplementation = Java.registerClass({
        name: "com.example.TextWatcher" + Math.floor(Math.random() * 1000),
        implements: [TextWatcher],
        methods: {
            beforeTextChanged: function(s, start, count, after) {},
            onTextChanged: function(s, start, before, count) {},
            afterTextChanged: function(editable) {
                callback(editable.toString());
            }
        }
    });
    
    editText.addTextChangedListener(TextWatcherImplementation.$new());
    this.#menuScrollLayout.addView(editText);
}



    

    addText(text, textSize, textColor) {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT);

        const margin = pixelDensityToPixels(this.#activity, 5);

        const textView = this.#classLoader.TextView.$new(this.#activity);



        textView.setText(this.#classLoader.String.$new(text));

        textView.setTextSize(textSize);

        textView.setTextColor(this.#classLoader.Color.parseColor(textColor));

        layoutParams.setMargins(0, 0, 0, margin);

        textView.setLayoutParams(layoutParams);



        this.#menuScrollLayout.addView(textView);

    }



    addSeekBar(textValue,initialValue, minValue, maxValue, callback) {

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);

        const margin = pixelDensityToPixels(this.#activity,1);

        const seekBar = this.#classLoader.SeekBar.$new(this.#activity, null, 0, Java.use("android.R$style").Widget_Holo_SeekBar.value);

        const textView = this.#classLoader.TextView.$new(this.#activity);

        seekBar.setMax(maxValue - minValue);

        seekBar.setProgress(0);

        layoutParams.setMargins(0, 0, 0, margin);

        seekBar.setLayoutParams(layoutParams);

        const text = Java.use("java.lang.String").$new(textValue+ " "+ initialValue);

        textView.setText(text)

        textView.setTextColor(this.#classLoader.Color.parseColor("#75757B"))

        seekBar.setProgress(initialValue);



        const SeekBarChangeListener = Java.use("android.widget.SeekBar$OnSeekBarChangeListener");

        const SeekBarChangeListenerImplementation = Java.registerClass({

            name: "com.example.SeekBarChangeListener" + Math.floor(Math.random() * 1000),

            implements: [SeekBarChangeListener],

            methods: {

                onProgressChanged(seekBar, progress, fromUser) {

                    const value = progress + minValue;

                    const text = Java.use("java.lang.String").$new(textValue+" "+value);



                    textView.setText(text);

                    callback(value,"move");

                },

                onStartTrackingTouch(seekBar) {

                    const progress = seekBar.getProgress()

                    const value = progress + minValue;

                    const text = Java.use("java.lang.String").$new(textValue+" "+value);



                    textView.setText(text);

                    callback(value,"start");



                },

                onStopTrackingTouch(seekBar) {

                    const progress = seekBar.getProgress()



                    const value = progress + minValue;

                    const text = Java.use("java.lang.String").$new(textValue+" "+value);



                    textView.setText(text);

                    callback(value,"end");

                }

            }

        });



        seekBar.setOnSeekBarChangeListener(SeekBarChangeListenerImplementation.$new());

        this.#menuScrollLayout.addView(textView);



        this.#menuScrollLayout.addView(seekBar);





        textView.setLayoutParams(layoutParams);

        textView.setGravity(this.#classLoader.Gravity.CENTER.value);

    }



    #createMainLayoutEvent() {

        const mainLayout = this.#mainLayout

        const menuLayout = this.#menuLayout

        const menuStart = this.#menuStart

        const classLoader = this.#classLoader

        let initialX = 0

        let initialY = 0

        let isMove = false

        let isMenuLayout = false

        let initialTouchTime = 0

        const MainLayoutOnTouchListener = Java.registerClass({

            name: "com.example.MainLayoutEvent",

            implements: [classLoader.View_OnTouchListener],

            methods: {

                onTouch(view, event) {

                    switch (event.getAction()) {

                        case classLoader.MotionEvent.ACTION_DOWN.value:

                            initialX = view.getX() - event.getRawX();

                            initialY = view.getY() - event.getRawY();

                            isMove = false

                            initialTouchTime = Date.now()

                            break

                        case classLoader.MotionEvent.ACTION_UP.value:

                            if (!isMove) {

                                if (!isMenuLayout) {

                                    mainLayout.removeView(menuStart)

                                    mainLayout.addView(menuLayout)

                                    isMenuLayout = true

                                } else {

                                    mainLayout.removeView(menuLayout)

                                    mainLayout.addView(menuStart)

                                    isMenuLayout = false

                                }

                            }

                            break

                        case classLoader.MotionEvent.ACTION_MOVE.value:

                            view.setX(event.getRawX() + initialX)

                            view.setY(event.getRawY() + initialY)

                            let deltaTime = Date.now() - initialTouchTime

                            if (deltaTime > 200) isMove = true

                            break

                        default:

                            return false

                    }

                    return true

                }

            }

        })

        this.#mainLayout.setOnTouchListener(MainLayoutOnTouchListener.$new())

    }



    start() {

        this.#drawContentView()

        this.#drawMainLayout()

        this.#drawMenuStart()

        this.#drawMenuBarLayout()

        this.#drawMenuBarTitle()

        this.#drawMenuOptions()

        this.#createMainLayoutEvent()

    }


}
































































Java.perform(function () {

    Java.scheduleOnMainThread(function () {

        const classLoader = getClassLoader()

        const mainActivity = getMainActivity(classLoader)

        const menu = new Menu(classLoader, mainActivity)

        // Set the title and color that will appear with the minimized menu.
        menu.createMenuStart("⚙️", 25, "#FFFFFF")

        // Set the menu layout color and size.
        menu.createMenuLayout("#333333", 300)

        // Set the menu bar color.
        menu.createMenuBarLayout("#000000")

        // Set the name and name color.
        menu.createMenuBarTitle("VORAZ MENU", "#FFFFFF", 30);

        // Set the color of on and off options.
        menu.createMenuOptionsLayout("#00FF00", "#CCCCCC")


        // Add options
        
        menu.addTextInput("Digite aqui", function(text) {
        
        })
        
        menu.addText("MENU PLAYER", 16, "#FFFFFF");
        
        menu.addOption("option1", "GOD MOD", {
            on: function () {
                // Add actions when the option is turned on
                const morto = Module.getBaseAddress("libil2cpp.so").add(0x688670)

Interceptor.attach(morto,{
  onEnter(args){
  
  args[0].add(0x18).readPointer().add(0x48).writeU8(1)
  
  }
})
            },
            off: function () {
                // Add actions when the option is turned off
                
                const morto = Module.getBaseAddress("libil2cpp.so").add(0x688670)

Interceptor.attach(morto,{
  onEnter(args){
  
  args[0].add(0x18).readPointer().add(0x48).writeU8(0)
  
  }
})
            }
        })
        
        menu.addOption("option2", "KILL ALL ZOMBIE", {
            on: function () {
                // Add actions when the option is turned on
                const playerStats = Module.getBaseAddress("libil2cpp.so").add(0x60397C)
        Interceptor.attach(playerStats,{
          onEnter(args){
        
         const enemyHealth = args[0].add(0x10).readPointer().add(0x14).readPointer()
        
         const die = Module.getBaseAddress("libil2cpp.so").add(0x5FE69C)
         const fDie = new NativeFunction(die,"void",["pointer"])
        
         fDie(enemyHealth)
        
        
         }
        })
            },
            off: function () {
                // Add actions when the option is turned off
                const playerStats = Module.getBaseAddress("libil2cpp.so").add(0x60397C)
      Interceptor.detachAll();
            }
        })
        
        menu.addOption("option3", "KILL ME", {
            on: function () {
                // Add actions when the option is turned on
                const playerStats3 = Module.getBaseAddress("libil2cpp.so").add(0x688670)
        Interceptor.attach(playerStats3,{
          onEnter(args){
       
          const diePlayer = args[0].add(0x18).readPointer()
          const dieYou = Module.getBaseAddress("libil2cpp.so").add(0x697F3C)
          const fdieYou = new NativeFunction(dieYou,"void",["pointer"])
        
          fdieYou(diePlayer)
      
      
          }
        })
            },
            off: function () {
                // Add actions when the option is turned off
                const playerStats3 = Module.getBaseAddress("libil2cpp.so").add(0x688670)
      Interceptor.detachAll();
            }
        })
        
                menu.addOption("option4", "GET FUEL | COIN", {
            on: function () {
                // Add actions when the option is turned on
                    const LibBaseFuelCoin = Module.getBaseAddress("libil2cpp.so").add(0x6AA3BC) 
   
      Interceptor.attach(LibBaseFuelCoin,{
    
        onEnter(args){

        const getFuel =  Module.getBaseAddress("libil2cpp.so").add(0x5EF394)
        const fgetFuel = new NativeFunction(getFuel,"void",["pointer"])

        fgetFuel(args[0])
   
        const getMoney =  Module.getBaseAddress("libil2cpp.so").add(0x5EF4D4)
        const fgetMoney = new NativeFunction(getMoney,"void",["pointer"])

        fgetMoney(args[0])
    

    
      }
    })
                
                
            },
            off: function () {
                // Add actions when the option is turned off
                    const LibBaseFuelCoin = Module.getBaseAddress("libil2cpp.so").add(0x6AA3BC)
                      Interceptor.detachAll();
                
            }
        })
        
        menu.addOption("option5", "GIANT PLAYER", {
            on: function () {
                // Add actions when the option is turned on
                const baselib = Module.getBaseAddress("libil2cpp.so").add(0x688670)

Interceptor.attach(baselib,{

    onEnter(args){

        const phontomView = args[0].add(0xC).readPointer().add(0x3C).readU8()
         
        const isMine =  Module.getBaseAddress("libil2cpp.so").add(0x1A0B69C)
        const fIsMine = new NativeFunction(isMine,"bool",["pointer"])

        if(phontomView == false){

            const compponent =  Module.getBaseAddress("libil2cpp.so").add(0x24909C0)
            const fcompponent = new NativeFunction(compponent,"pointer",["pointer"])
    
            let transform =  fcompponent(args[0])
    
           
            const setScale = Module.getBaseAddress("libil2cpp.so").add(0x249F940)
            const fsetScale = new NativeFunction(setScale,"void",["pointer","float","float","float"])
             
            fsetScale(transform,4.6,45.0,4.6)
               
       
        }else{

        }
    }
})
                
                
            },
            off: function () {
                // Add actions when the option is turned off
                const baselib = Module.getBaseAddress("libil2cpp.so").add(0x688670)

             Interceptor.attach(baselib,{

                 onEnter(args){

                     const phontomView = args[0].add(0xC).readPointer().add(0x3C).readU8()
         
                     const isMine =  Module.getBaseAddress("libil2cpp.so").add(0x1A0B69C)
                     const fIsMine = new NativeFunction(isMine,"bool",["pointer"])

                     if(phontomView == false){

                         const compponent =  Module.getBaseAddress("libil2cpp.so").add(0x24909C0)
                         const fcompponent = new NativeFunction(compponent,"pointer",["pointer"])
    
                         let transform =  fcompponent(args[0])
    
           
                         const setScale = Module.getBaseAddress("libil2cpp.so").add(0x249F940)
                         const fsetScale = new NativeFunction(setScale,"void",["pointer","float","float","float"])
             
                         fsetScale(transform,1.6,1.6,1.6)
               
       
                     }else{

                     }
                 }
             })
                
                
            }
        })
        
        menu.addOption("option6", "TP KILL", {
            on: function () {
                // Add actions when the option is turned on
                var posx
                var posy
                var posz
                const baselib = Module.getBaseAddress("libil2cpp.so").add(0x688670)

                Interceptor.attach(baselib,{

                    onEnter(args){

                const phontomView = args[0].add(0xC).readPointer().add(0x3C).readU8()

                const compponent =  Module.getBaseAddress("libil2cpp.so").add(0x24909C0)
                const fcompponent = new NativeFunction(compponent,"pointer",["pointer"])

                let transform =  fcompponent(args[0])

                let vect = Memory.alloc(3*4)

                        if(phontomView == false){

                        const localPosition = Module.getBaseAddress("libil2cpp.so").add(0x249EA38)
                        const flocalPosition = new NativeFunction(localPosition,"void",["pointer","pointer"])

                        flocalPosition(transform,vect)

                        posx = vect.readFloat()
                        posy = vect.add(4).readFloat()
                        posz = vect.add(8).readFloat()

                    }
                    const setPosition = Module.getBaseAddress("libil2cpp.so").add(0x249E90C)
                    const fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])
   
                    fsetPosition(transform,posx,posy,posz)

                    }
                })
            },
            off: function () {
                // Add actions when the option is turned off
                const baselib = Module.getBaseAddress("libil2cpp.so").add(0x688670)
                      Interceptor.detachAll();
                
            }
        })
        
        
        menu.addText(" MENU WEAPON", 16, "#FFFFFF");

        menu.addOption("option7", "NO RECOIL", {
            on: function () {
                // Add actions when the option is turned on
                const semrecoil = Module.getBaseAddress("libil2cpp.so").add(0x688670)
        Interceptor.attach(semrecoil,{
          onEnter(args){
        
         args[0].add(0x24).readPointer().add(0x2C).readPointer().add(0x18).readPointer().add(0x20).writeFloat(0)
         args[0].add(0x24).readPointer().add(0x2C).readPointer().add(0x18).readPointer().add(0x24).writeFloat(0)
         args[0].add(0x24).readPointer().add(0x2C).readPointer().add(0x18).readPointer().add(0x28).writeFloat(0)
          }
        })
            },
            off: function () {
                // Add actions when the option is turned off
                const semrecoil = Module.getBaseAddress("libil2cpp.so").add(0x688670)
        Interceptor.attach(semrecoil,{
          onEnter(args){
        
         args[0].add(0x24).readPointer().add(0x2C).readPointer().add(0x18).readPointer().add(0x20).writeFloat(0.20000000298023224)
         args[0].add(0x24).readPointer().add(0x2C).readPointer().add(0x18).readPointer().add(0x24).writeFloat(0.5)
         args[0].add(0x24).readPointer().add(0x2C).readPointer().add(0x18).readPointer().add(0x28).writeFloat(0)
          }
        })
            }
        })
        
        
        menu.addText("TELEPORT NOMISK", 16, "#FFFFFF");
        
        menu.addOption("option8", "CENTER CITY", {
            on: function () {
                // Add actions when the option is turned on
                const baselib2 = Module.getBaseAddress("libil2cpp.so").add(0x688670)

                    Interceptor.attach(baselib2,{

                        onEnter(args){

                            const compponent =  Module.getBaseAddress("libil2cpp.so").add(0x24909C0)
                            const fcompponent = new NativeFunction(compponent,"pointer",["pointer"])
    
                            let transform =  fcompponent(args[0])
    
           
                            const setPosition = Module.getBaseAddress("libil2cpp.so").add(0x249E90C)
                            const fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])
             
                            fsetPosition(transform,453.8675842285156,116.40999603271484,498.30303955078125)

                        }
                    })
            },
            off: function () {
                // Add actions when the option is turned off
                const baselib2 = Module.getBaseAddress("libil2cpp.so").add(0x688670)
                      Interceptor.detachAll();
            }
        })
        
        menu.addOption("option9", "EXTRAÇÃO", {
            on: function () {
                // Add actions when the option is turned on
                const baselib = Module.getBaseAddress("libil2cpp.so").add(0x688670)

                    Interceptor.attach(baselib,{

                        onEnter(args){

                            const compponent =  Module.getBaseAddress("libil2cpp.so").add(0x24909C0)
                            const fcompponent = new NativeFunction(compponent,"pointer",["pointer"])
    
                            let transform =  fcompponent(args[0])
    
           
                            const setPosition = Module.getBaseAddress("libil2cpp.so").add(0x249E90C)
                            const fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])
             
                            fsetPosition(transform,154.3650360107422,113.21358489990234,485.50927734375)

                        }
                    })
            },
            off: function () {
                // Add actions when the option is turned off
                const baselib = Module.getBaseAddress("libil2cpp.so").add(0x688670)
                      Interceptor.detachAll();
            }
        })
        
       
              menu.addText("TELEPORT VALLEY ", 16, "#FFFFFF");
        
        menu.addOption("option10", "CENTER CITY", {
            on: function () {
                // Add actions when the option is turned on
                const baselib3 = Module.getBaseAddress("libil2cpp.so").add(0x688670)

                    Interceptor.attach(baselib3,{

                        onEnter(args){

                            const compponent =  Module.getBaseAddress("libil2cpp.so").add(0x24909C0)
                            const fcompponent = new NativeFunction(compponent,"pointer",["pointer"])
    
                            let transform =  fcompponent(args[0])
    
           
                            const setPosition = Module.getBaseAddress("libil2cpp.so").add(0x249E90C)
                            const fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])
             
                            fsetPosition(transform,521.9363403320313,85.45307159423828,430.6603698730469)

                        }
                    })
            },
            off: function () {
                // Add actions when the option is turned off
                const baselib3 = Module.getBaseAddress("libil2cpp.so").add(0x688670)
                      Interceptor.detachAll();
            }
        })
        
        menu.addOption("option11", "EXTRAÇÃO", {
            on: function () {
                // Add actions when the option is turned on
                const baselib4 = Module.getBaseAddress("libil2cpp.so").add(0x688670)

                    Interceptor.attach(baselib4,{

                        onEnter(args){

                            const compponent =  Module.getBaseAddress("libil2cpp.so").add(0x24909C0)
                            const fcompponent = new NativeFunction(compponent,"pointer",["pointer"])
    
                            let transform =  fcompponent(args[0])
    
           
                            const setPosition = Module.getBaseAddress("libil2cpp.so").add(0x249E90C)
                            const fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])
             
                            fsetPosition(transform,151.2646026611328,110.85526275634766,535.8716430664063)

                        }
                    })
 
            },
            off: function () {
                // Add actions when the option is turned off
                const baselib4 = Module.getBaseAddress("libil2cpp.so").add(0x688670)
                      Interceptor.detachAll();
            }
        })
        
        
        
        menu.addText("MENU LIFE | ESTAMINA", 16, "#FFFFFF");
        
        

        
            // Endere莽o base para modificar vida e estamina
        const baseAddress = Module.getBaseAddress("libil2cpp.so").add(0x688670);

        // Vari谩veis para controlar os interceptores e os valores da vida e da estamina
        let lifeInterceptor = null;
        let staminaInterceptor = null;
        let lifeValue = 0;
        let staminaValue = 0;

        // Fun莽茫o para modificar vida e estamina
        function setLifeAndStamina(value, offset) {
            if (value >= 2) {
                if (offset === 0x18) {
                    // Modificar a vida
                    if (!lifeInterceptor) {
                        // Anexar o interceptor para modificar a vida
                        lifeInterceptor = Interceptor.attach(baseAddress, {
                            onEnter(args) {
                                // Salvar o valor atual da vida
                                lifeValue = args[0].add(0x18).readPointer().add(0x18).readFloat();
                                // Modificar o valor da vida
                                args[0].add(0x18).readPointer().add(offset).writeFloat(value);
                            }
                        });
                    }
                } else {
                    // Modificar a estamina
                    if (!staminaInterceptor) {
                        // Anexar o interceptor para modificar a estamina
                        staminaInterceptor = Interceptor.attach(baseAddress, {
                            onEnter(args) {
                                // Salvar o valor atual da estamina
                                staminaValue = args[0].add(0x18).readPointer().add(0x1C).readFloat();
                                // Modificar o valor da estamina
                                args[0].add(0x18).readPointer().add(offset).writeFloat(value);
                            }
                        });
                    }
                }
            } else {
                if (offset === 0x18) {
                    // Parar de modificar a vida
                    if (lifeInterceptor) {
                        // Desanexar o interceptor da vida
                        lifeInterceptor.detach();
                        lifeInterceptor = null;
                    }
                } else {
                    // Parar de modificar a estamina
                    if (staminaInterceptor) {
                        // Desanexar o interceptor da estamina
                        staminaInterceptor.detach();
                        staminaInterceptor = null;
                    }
                }
            }
        }

        // Adicionando a barra para modificar a vida
        menu.addSeekBar("SET LIFE:", 1, 1, 99, function(changed, state) {
            if (state === "end") {
                setLifeAndStamina(changed, 0x18);
            }
        });

        // Adicionando a barra para modificar a estamina
        menu.addSeekBar("SET ESTAMINA:", 1, 1, 99, function(changed, state) {
            if (state === "end") {
                setLifeAndStamina(changed, 0x1C);
            }
        });

        // Interceptores para restaurar vida e estamina quando desativadas
        Interceptor.attach(baseAddress, {
            onEnter(args) {
                // Restaurar a vida para o valor salvo anteriormente
                if (!lifeInterceptor && staminaInterceptor !== null) {
                    args[0].add(0x18).readPointer().add(0x18).writeFloat(lifeValue);
                }
                // Restaurar a estamina para o valor salvo anteriormente
                if (!staminaInterceptor && lifeInterceptor !== null) {
                    args[0].add(0x18).readPointer().add(0x1C).writeFloat(staminaValue);
                }
            }
        });

        menu.start()

    })

})