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
        menu.createMenuBarTitle("WZ BasicMenu", "#FFFFFF", 30);

        // Set the color of on and off options.
        menu.createMenuOptionsLayout("#00FF00", "#CCCCCC")


        // Add options
        
        menu.addText("MENU TELEPORT", 16, "#FFFFFF");
        
        menu.addOption("option1", "TP X", {
            on: function () {
                let colisionEnable = Module.getBaseAddress("libil2cpp.so").add(0x29C5C98)
let fcolisionEnable = new NativeFunction(colisionEnable,"void",["pointer","bool"])

var posx 
var posy
var posz

let vect 

let compponent =  Module.getBaseAddress("libil2cpp.so").add(0x29315B8)
let fcompponent = new NativeFunction(compponent,"pointer",["pointer"]) 


let pushLocalPosition = Module.getBaseAddress("libil2cpp.so").add(0x29429A0)
let fPushLocalPostion = new NativeFunction(pushLocalPosition,"void",["pointer","pointer"])


let setPosition = Module.getBaseAddress("libil2cpp.so").add(0x2942B74)
let fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])

const base = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)

Interceptor.attach(base,{
    onEnter(args){
     vect = Memory.alloc(3*4)
   
     let transform = fcompponent(args[0])
     
     fPushLocalPostion(transform,vect)

    posx = vect.readFloat()+0.2
    posy = vect.add(0x4).readFloat()
    posz = vect.add(0x8).readFloat()

     fsetPosition(transform,posx,posy,posz)

    }})

            },
            off: function () {
              const baselib = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)
                      Interceptor.detachAll();

            }
        })
        
                menu.addOption("option2", "TP Y", {
            on: function () {
      let colisionEnable = Module.getBaseAddress("libil2cpp.so").add(0x29C5C98)
let fcolisionEnable = new NativeFunction(colisionEnable,"void",["pointer","bool"])

var posx 
var posy
var posz

let vect 

let compponent =  Module.getBaseAddress("libil2cpp.so").add(0x29315B8)
let fcompponent = new NativeFunction(compponent,"pointer",["pointer"]) 


let pushLocalPosition = Module.getBaseAddress("libil2cpp.so").add(0x29429A0)
let fPushLocalPostion = new NativeFunction(pushLocalPosition,"void",["pointer","pointer"])


let setPosition = Module.getBaseAddress("libil2cpp.so").add(0x2942B74)
let fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])

const base = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)

Interceptor.attach(base,{
    onEnter(args){
     vect = Memory.alloc(3*4)
   
     let transform = fcompponent(args[0])
     
     fPushLocalPostion(transform,vect)

    posx = vect.readFloat()
    posy = vect.add(0x4).readFloat()+2
    posz = vect.add(0x8).readFloat()

     fsetPosition(transform,posx,posy,posz)

    }})

            },
            off: function () {
            const baselib = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)
                      Interceptor.detachAll();

            }
        })
        
                menu.addOption("option3", "TP Z", {
            on: function () {
             let colisionEnable = Module.getBaseAddress("libil2cpp.so").add(0x29C5C98)
let fcolisionEnable = new NativeFunction(colisionEnable,"void",["pointer","bool"])

var posx 
var posy
var posz

let vect 

let compponent =  Module.getBaseAddress("libil2cpp.so").add(0x29315B8)
let fcompponent = new NativeFunction(compponent,"pointer",["pointer"]) 


let pushLocalPosition = Module.getBaseAddress("libil2cpp.so").add(0x29429A0)
let fPushLocalPostion = new NativeFunction(pushLocalPosition,"void",["pointer","pointer"])


let setPosition = Module.getBaseAddress("libil2cpp.so").add(0x2942B74)
let fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])

const base = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)

Interceptor.attach(base,{
    onEnter(args){
     vect = Memory.alloc(3*4)
   
     let transform = fcompponent(args[0])
     
     fPushLocalPostion(transform,vect)

    posx = vect.readFloat()
    posy = vect.add(0x4).readFloat()
    posz = vect.add(0x8).readFloat()+0.2

     fsetPosition(transform,posx,posy,posz)


    }})
            },
            off: function () {
            const baselib = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)
                      Interceptor.detachAll();

            }
        })
      menu.addOption("option4", "NoRecoil", {
            on: function () {
            let colisionEnable = Module.getBaseAddress("libil2cpp.so").add(0x29C5C98)
let fcolisionEnable = new NativeFunction(colisionEnable,"void",["pointer","bool"])

var posx 
var posy
var posz

let vect 

let compponent =  Module.getBaseAddress("libil2cpp.so").add(0x29315B8)
let fcompponent = new NativeFunction(compponent,"pointer",["pointer"]) 


let pushLocalPosition = Module.getBaseAddress("libil2cpp.so").add(0x29429A0)
let fPushLocalPostion = new NativeFunction(pushLocalPosition,"void",["pointer","pointer"])


let setPosition = Module.getBaseAddress("libil2cpp.so").add(0x2942B74)
let fsetPosition = new NativeFunction(setPosition,"void",["pointer","float","float","float"])

const base = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)


Interceptor.attach(base,{
    onEnter(args){
 
const arma = args[0].add(0x110).readPointer().add(0x140).readPointer()

arma.add(0x1C4).writeFloat(0)

arma.add(0x1C8).writeFloat(0)

arma.add(0x1DC).writeFloat(0)

arma.add(0x1E0).writeFloat(0)

arma.add(0x1C4).writeFloat(0)

    }})
            },
            off: function () {
            const baselib = Module.getBaseAddress("libil2cpp.so").add(0x8CA42C)
                      Interceptor.detachAll();

            }
        })


        menu.start()

    })

})
