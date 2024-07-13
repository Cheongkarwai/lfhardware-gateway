package com.lfhardware.gateway.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
public class TestApi {

    @GetMapping("/test")
    public String test(){
     String keyword = "apple | Apple";

     List<Test> arrayList = new ArrayList<>();
     Test test = new Test();
     test.setCount(10);
        Test test1 = new Test();
     test1.setCount(5);
     Test test2 = new Test();
     test2.setCount(2);
        arrayList.add(test);
     arrayList.add(test1);
     arrayList.add(test2);
    List<Test> testa = arrayList.stream().sorted((o1, o2) -> Integer.compare(o2.getCount(),o1.getCount()))
            .limit(10)
            .toList();

    testa.forEach(System.out::println);
     StringBuffer stringBuffer = new StringBuffer();
     stringBuffer.append(keyword.charAt(0));
        Pattern pattern = Pattern.compile(keyword);
        Matcher matcher = pattern.matcher("apple");

        System.out.println(matcher.group());
        while(matcher.find()){
            for(int i = 0;i < matcher.groupCount(); i++){
                System.out.println(matcher.find(0));
            }
        }


        return "Hi";
    }
}

class Test{

    private String test;

    public String getTest() {
        return test;
    }

    public void setTest(String test) {
        this.test = test;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    private int count;

    @Override
    public String toString(){
        System.out.println(count);
        return String.valueOf(count);
    }
}
