Java.perform(function () { 

    Java.scheduleOnMainThread(function() {
            var toast = Java.use("android.widget.Toast");
            toast.makeText(Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(), Java.use("java.lang.String").$new("GABRIEL ESTÁ FUNCIONANDO✓✓"), 1).show();
    });
}); 
