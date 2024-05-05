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
        SeekBar: Java.use("android.widget.SeekBar"),
        EditText: Java.use("android.widget.EditText") // Adicionando definição para EditText
    };
    return classLoader;
}

function pixelDensityToPixels(context, dp) {
    const density = context.getResources().getDisplayMetrics().density.value;
    return parseInt(dp * density);
}

function getMainActivity(classLoader) {
    const activityThread = classLoader.ActivityThread.sCurrentActivityThread.value;
    const mActivities = activityThread.mActivities.value;
    const activityClientRecord = Java.cast(mActivities.valueAt(0), classLoader.ActivityThread_ActivityClientRecord);
    return activityClientRecord.activity.value;
}

class Menu {
    #classLoader;
    #activity;
    #MATCH_PARENT;
    #WRAP_CONTENT;
    #mainLayout;
    #menuLayout;
    #menuBarLayout;
    #menuBarTitle;
    #menuScroll;
    #menuOptions;
    #options;
    #contentView;
    #colorOn;
    #colorOff;

    constructor(classLoader, activity) {
        this.#classLoader = classLoader;
        this.#activity = activity;
        this.#MATCH_PARENT = classLoader.LinearLayout_LayoutParams.MATCH_PARENT.value;
        this.#WRAP_CONTENT = classLoader.LinearLayout_LayoutParams.WRAP_CONTENT.value;
        this.#options = {};
        this.#createContentView();
        this.#createMainLayout();
        this.#createMenuScroll();
    }

    #createContentView() {
        this.#contentView = this.#classLoader.LinearLayout.$new(this.#activity);
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#MATCH_PARENT);
        this.#contentView.setLayoutParams(layoutParams);
        this.#contentView.setGravity(this.#classLoader.Gravity.CENTER.value);
        this.#contentView.setBackgroundColor(this.#classLoader.Color.TRANSPARENT.value);
    }

    #createMainLayout() {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT);
        this.#mainLayout = this.#classLoader.LinearLayout.$new(this.#activity);
        this.#mainLayout.setLayoutParams(layoutParams);
    }

    #createMenuScroll() {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);
        this.#menuScroll = this.#classLoader.ScrollView.$new(this.#activity);
        const padding = pixelDensityToPixels(this.#activity, 8);
        this.#menuScroll.setLayoutParams(layoutParams);
        this.#menuScroll.setPadding(padding, padding, padding, padding);
        this.#menuScroll.mFillViewport.value = true;
    }

    createMenuOptionsLayout(colorOn, colorOff) {
        this.#createMenuScroll();
        this.#createMenuScrollLayout();
        this.#colorOn = colorOn;
        this.#colorOff = colorOff;
    }

    createMenuStart(title, size, color) {
        size = pixelDensityToPixels(this.#activity, size);
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#WRAP_CONTENT, this.#WRAP_CONTENT);
        this.#menuStart = this.#classLoader.TextView.$new(this.#activity);
        this.#menuStart.setLayoutParams(layoutParams);
        this.#menuStart.setText(this.#classLoader.String.$new(title));
        this.#menuStart.setTextSize(size);
        this.#menuStart.setTextColor(this.#classLoader.Color.parseColor(color));
    }

    createMenuLayout(color, size) {
        const SIZE_DP = pixelDensityToPixels(this.#activity, size);
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(SIZE_DP, SIZE_DP);
        this.#menuLayout = this.#classLoader.LinearLayout.$new(this.#activity);
        this.#menuLayout.setLayoutParams(layoutParams);
        this.#menuLayout.setBackgroundColor(this.#classLoader.Color.parseColor(color));
        this.#menuLayout.setOrientation(this.#menuLayout.VERTICAL.value);
    }

    createMenuBarLayout(color) {
        const padding = pixelDensityToPixels(this.#activity, 10);
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);
        this.#menuBarLayout = this.#classLoader.LinearLayout.$new(this.#activity);
        this.#menuBarLayout.setLayoutParams(layoutParams);
        this.#menuBarLayout.setBackgroundColor(this.#classLoader.Color.parseColor(color));
        this.#menuBarLayout.setPadding(padding, padding, 0, padding);
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
        this.#activity.addContentView(this.#contentView, this.#contentView.getLayoutParams());
    }

    #drawMainLayout() {
        this.#contentView.addView(this.#mainLayout);
    }

    #drawMenuStart() {
        this.#mainLayout.addView(this.#menuStart);
    }

    #drawMenuLayout() {
        this.#mainLayout.addView(this.#menuLayout);
    }

    #drawMenuBarLayout() {
        this.#menuLayout.addView(this.#menuBarLayout);
    }

    #drawMenuBarTitle() {
        this.#menuBarLayout.addView(this.#menuBarTitle);
    }

    #drawMenuOptions() {
        this.#menuLayout.addView(this.#menuScroll);
        this.#menuScroll.addView(this.#menuScrollLayout);
    }

    #createOptionClickEvent(id, optionView, callbacks) {
        const classLoader = this.#classLoader;
        let optionState = false;
        const colorOn = this.#colorOn;
        const colorOff = this.#colorOff;
        const optionOnClickListener = Java.registerClass({
            name: "com.example." + id,
            implements: [classLoader.View_OnClickListener],
            methods: {
                onClick(p1) {
                    if (!optionState) {
                        p1.setBackgroundColor(classLoader.Color.parseColor(colorOn));
                        optionState = true;
                        callbacks.on();
                    } else {
                        p1.setBackgroundColor(classLoader.Color.parseColor(colorOff));
                        optionState = false;
                        callbacks.off();
                    }
                }
            }
        });
        optionView.setOnClickListener(optionOnClickListener.$new());
    }

    addOption(id, name, callbacks) {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);
        const padding = pixelDensityToPixels(this.#activity, 5);
        const option = this.#classLoader.TextView.$new(this.#activity);
        const margin = pixelDensityToPixels(this.#activity, 10);
        option.setText(this.#classLoader.String.$new(name));
        option.setBackgroundColor(this.#classLoader.Color.parseColor(this.#colorOff));
        option.setTextColor(this.#classLoader.Color.parseColor("#75757B"));
        layoutParams.setMargins(0, 0, 0, margin);
        option.setLayoutParams(layoutParams);
        option.setPadding(padding, padding, 0, padding);
        this.#menuScrollLayout.addView(option);
        this.#createOptionClickEvent(id, option, callbacks);
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

    addSeekBar(textValue, initialValue, minValue, maxValue, callback) {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);
        const margin = pixelDensityToPixels(this.#activity, 1);
        const seekBar = this.#classLoader.SeekBar.$new(this.#activity, null, 0, Java.use("android.R$style").Widget_Holo_SeekBar.value);
        const textView = this.#classLoader.TextView.$new(this.#activity);
        seekBar.setMax(maxValue - minValue);
        seekBar.setProgress(0);
        layoutParams.setMargins(0, 0, 0, margin);
        seekBar.setLayoutParams(layoutParams);
        const text = Java.use("java.lang.String").$new(textValue + " " + initialValue);
        textView.setText(text);
        textView.setTextColor(this.#classLoader.Color.parseColor("#75757B"));
        seekBar.setProgress(initialValue);
        const SeekBarChangeListener = Java.use("android.widget.SeekBar$OnSeekBarChangeListener");
        const SeekBarChangeListenerImplementation = Java.registerClass({
            name: "com.example.SeekBarChangeListener" + Math.floor(Math.random() * 1000),
            implements: [SeekBarChangeListener],
            methods: {
                onProgressChanged(seekBar, progress, fromUser) {
                    const value = progress + minValue;
                    const text = Java.use("java.lang.String").$new(textValue + " " + value);
                    textView.setText(text);
                    callback(value, "move");
                },
                onStartTrackingTouch(seekBar) {
                    const progress = seekBar.getProgress();
                    const value = progress + minValue;
                    const text = Java.use("java.lang.String").$new(textValue + " " + value);
                    textView.setText(text);
                    callback(value, "start");
                },
                onStopTrackingTouch(seekBar) {
                    const progress = seekBar.getProgress();
                    const value = progress + minValue;
                    const text = Java.use("java.lang.String").$new(textValue + " " + value);
                    textView.setText(text);
                    callback(value, "end");
                }
            }
        });
        seekBar.setOnSeekBarChangeListener(SeekBarChangeListenerImplementation.$new());
        this.#menuScrollLayout.addView(textView);
        this.#menuScrollLayout.addView(seekBar);
        textView.setLayoutParams(layoutParams);
        textView.setGravity(this.#classLoader.Gravity.CENTER.value);
    }

    addTextInput(hint, callback) {
        const layoutParams = this.#classLoader.LinearLayout_LayoutParams.$new(this.#MATCH_PARENT, this.#WRAP_CONTENT);
        const margin = pixelDensityToPixels(this.#activity, 1);
        const editText = this.#classLoader.EditText.$new(this.#activity);
        editText.setHint(this.#classLoader.String.$new(hint));
        layoutParams.setMargins(0, 0, 0, margin);
        editText.setLayoutParams(layoutParams);
        this.#menuScrollLayout.addView(editText);
        editText.addTextChangedListener(
            Java.use("android.text.TextWatcher").$new({
                afterTextChanged: function (editable) {},
                beforeTextChanged: function (s, start, count, after) {},
                onTextChanged: function (s, start, before, count) {
                    callback(s.toString());
                }
            })
        );
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
                onTouch(view, event) {
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
        this.#mainLayout.setOnTouchListener(MainLayoutOnTouchListener.$new());
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

// Exemplo de uso
const classLoader = getClassLoader();
const activity = getMainActivity(classLoader);
const menu = new Menu(classLoader, activity);
menu.createMenuOptionsLayout("#0000FF", "#FF0000"); // Define as cores dos itens do menu
menu.createMenuStart("Menu", 20, "#000000"); // Define o título do menu
menu.createMenuLayout("#FFFFFF", 15); // Define a cor e o tamanho do layout do menu
menu.createMenuBarLayout("#CCCCCC"); // Define a cor do layout da barra do menu
menu.createMenuBarTitle("Floating Menu", "#000000, 18); // Define o título da barra do menu
menu.addOption("option1", "Option 1", {
    on: function () {
        console.log("Option 1 is ON");
    },
    off: function () {
        console.log("Option 1 is OFF");
    }
}); // Adiciona a primeira opção do menu
menu.addOption("option2", "Option 2", {
    on: function () {
        console.log("Option 2 is ON");
    },
    off: function () {
        console.log("Option 2 is OFF");
    }
}); // Adiciona a segunda opção do menu
menu.addOption("option3", "Option 3", {
    on: function () {
        console.log("Option 3 is ON");
    },
    off: function () {
        console.log("Option 3 is OFF");
    }
}); // Adiciona a terceira opção do menu
menu.addTextInput("Enter your key", function (key) {
    console.log("Entered key: " + key);
}); // Adiciona um campo de entrada de texto
menu.start(); // Inicia o menu