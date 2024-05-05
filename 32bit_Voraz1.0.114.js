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

        const padding = this.pixelDensityToPixels(8)

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

        size = this.pixelDensityToPixels(size)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT)

        this.#menuStart = this.#classLoader.TextView.$new(this.#activity)

        this.#menuStart.setLayoutParams(layoutParams)

        this.#menuStart.setText(this.#classLoader.String.$new(title))

        this.#menuStart.setTextSize(size)

        this.#menuStart.setTextColor(this.#classLoader.Color.parseColor(color))

    }

    createMenuLayout(color, size) {

        const SIZE_DP = this.pixelDensityToPixels(size)

        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(SIZE_DP, SIZE_DP)

        this.#menuLayout = this.#classLoader.LinearLayout.$new(this.#activity)

        this.#menuLayout.setLayoutParams(layoutParams)

        this.#menuLayout.setBackgroundColor(this.#classLoader.Color.parseColor(color))

        this.#menuLayout.setOrientation(this.#menuLayout.VERTICAL.value)

    }

    createMenuBarLayout(color) {

        const padding = this.pixelDensityToPixels(10)

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

    addButton(text, callback) {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);

        const button = this.#classLoader.Button.$new(this.#activity);

        button.setText(this.#classLoader.String.$new(text));

        button.setOnClickListener(new this.#classLoader.View.OnClickListener({
            onClick(view) {
                callback();
            }
        }));

        this.#menuScrollLayout.addView(button);

        button.setLayoutParams(layoutParams);
    }

    addTextInput(hint) {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);

        const editText = this.#classLoader.EditText.$new(this.#activity);

        editText.setHint(this.#classLoader.String.$new(hint));

        this.#menuScrollLayout.addView(editText);

        editText.setLayoutParams(layoutParams);

        return {
            getText: function () {
                return editText.getText().toString}
    }

    addText(text, textSize, textColor) {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT);

        const margin = this.pixelDensityToPixels(5);

        const textView = this.#classLoader.TextView.$new(this.#activity);

        textView.setText(this.#classLoader.String.$new(text));

        textView.setTextSize(textSize);

        textView.setTextColor(this.#classLoader.Color.parseColor(textColor));

        layoutParams.setMargins(0, 0, 0, margin);

        textView.setLayoutParams(layoutParams);

        this.#menuScrollLayout.addView(textView);
    }

    addSeekBar(textValue, initialValue, minValue, maxValue, callback) {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);

        const margin = this.pixelDensityToPixels(1);

        const seekBar = this.#classLoader.SeekBar.$new(this.#activity, null, 0, this.#classLoader.android.R.style.Widget_Holo_SeekBar);

        const textView = this.#classLoader.TextView.$new(this.#activity);

        seekBar.setMax(maxValue - minValue);

        seekBar.setProgress(0);

        layoutParams.setMargins(0, 0, 0, margin);

        seekBar.setLayoutParams(layoutParams);

        const text = this.#classLoader.String.$new(textValue + " " + initialValue);

        textView.setText(text);

        textView.setTextColor(this.#classLoader.Color.parseColor("#75757B"));

        seekBar.setProgress(initialValue);

        const SeekBarChangeListener = this.#classLoader.SeekBar.OnSeekBarChangeListener;

        const SeekBarChangeListenerImplementation = Java.registerClass({
            name: "com.example.SeekBarChangeListener" + Math.floor(Math.random() * 1000),
            implements: [SeekBarChangeListener],
            methods: {
                onProgressChanged: function (seekBar, progress, fromUser) {
                    const value = progress + minValue;
                    const text = this.#classLoader.String.$new(textValue + " " + value);
                    textView.setText(text);
                    callback(value, "move");
                },
                onStartTrackingTouch: function (seekBar) {
                    const progress = seekBar.getProgress();
                    const value = progress + minValue;
                    const text = this.#classLoader.String.$new(textValue + " " + value);
                    textView.setText(text);
                    callback(value, "start");
                },
                onStopTrackingTouch: function (seekBar) {
                    const progress = seekBar.getProgress();
                    const value = progress + minValue;
                    const text = this.#classLoader.String.$new(textValue + " " + value);
                    textView.setText(text);
                    callback(value, "end");
                }
            }
        });

        seekBar.setOnSeekBarChangeListener(new SeekBarChangeListenerImplementation());

        this.#menuScrollLayout.addView(textView);
        this.#menuScrollLayout.addView(seekBar);

        textView.setLayoutParams(layoutParams);
        textView.setGravity(this.#classLoader.Gravity.CENTER.value);
    }

    pixelDensityToPixels(dp) {
        const density = this.#activity.getResources().getDisplayMetrics().density.value;
        return parseInt(dp * density);
    }

    #createMainLayoutEvent() {
        const mainLayout = this.#mainLayout;
        const menuLayout = this.#menuLayout;
        const menuStart = this.#menuStart;
        const classLoader = this.#classLoader;
        let initialX = 0;
        let initialY = 0;
        let isMove = false;
        let isMenuLayout = false;
        let initialTouchTime = 0;
        const MainLayoutOnTouchListener = Java.registerClass({
            name: "com.example.MainLayoutEvent",
            implements: [classLoader.View_OnTouchListener],
            methods: {
                onTouch: function (view, event) {
                    switch (event.getAction()) {
                        case classLoader.MotionEvent.ACTION_DOWN.value:
                            initialX = view.getX() - event.getRawX();
                            initialY = view.getY() - event.getRawY();
                            isMove = false;
                            initialTouchTime = Date.now();
                            break;
                        case classLoader.MotionEvent.ACTION_UP.value:
                            if (!isMove) {
                                if (!isMenuLayout) {
                                    mainLayout.removeView(menuStart);
                                    mainLayout.addView(menuLayout);
                                    isMenuLayout = true;
                                } else {
                                    mainLayout.removeView(menuLayout);
                                    mainLayout.addView(menuStart);
                                    isMenuLayout = false;
                                }
                            }
                            break;
                        case classLoader.MotionEvent.ACTION_MOVE.value:
                            view.setX(event.getRawX() + initialX);
                            view.setY(event.getRawY() + initialY);
                            let deltaTime = Date.now() - initialTouchTime;
                            if (deltaTime > 200) isMove = true;
                            break;
                        default:
                            return false;
                    }
                    return true;
                }
            }
        });

        this.#mainLayout.setOnTouchListener(new MainLayoutOnTouchListener());
    }

    start() {
        this.#drawContentView();
        this.#drawMainLayout();
        this.#drawMenuStart();
        this.#drawMenuBarLayout();
        this.#drawMenuBarTitle();
        this.#drawMenuOptions();
        this.#createMainLayoutEvent();
    }
}








Java.perform(function () {

    Java.scheduleOnMainThread(function () {

        const classLoader = getClassLoader()

        const mainActivity = getMainActivity(classLoader)

        const menu = new Menu(classLoader, mainActivity)

        // Função para iniciar o menu após verificar a chave
        function startMenu(key) {
            if (verifyKey(key)) {
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
                menu.addText("MENU PLAYER", 16, "#FFFFFF");

                menu.addOption("option1", "GOD MOD", {
                    on: function () {
                        // Add actions when the option is turned on
                        const morto = Module.getBaseAddress("libil2cpp.so").add(0x688670)
                        Interceptor.attach(morto, {
                            onEnter(args) {
                                args[0].add(0x18).readPointer().add(0x48).writeU8(1)
                            }
                        })
                    },
                    off: function () {
                        // Add actions when the option is turned off
                        const morto = Module.getBaseAddress("libil2cpp.so").add(0x688670)
                        Interceptor.attach(morto, {
                            onEnter(args) {
                                args[0].add(0x18).readPointer().add(0x48).writeU8(0)
                            }
                        })
                    }
                })

                // Add more options here...

                menu.start()
            } else {
                console.log("Chave inválida!");
            }
        }

        // Função para mostrar a caixa de texto para inserir a chave
        function showKeyInput() {
            const key = menu.addTextInput("Insira a chave:");
            menu.addButton("Enviar", function () {
                const enteredKey = key.getText();
                startMenu(enteredKey);
            });
        }

        // Mostrar a caixa de texto para inserir a chave
        showKeyInput();

    })
})