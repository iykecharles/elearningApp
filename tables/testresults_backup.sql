PGDMP                         {        	   elearning    13beta3    13beta3     K           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            L           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            M           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            N           1262    107822 	   elearning    DATABASE     m   CREATE DATABASE elearning WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'English_United States.1252';
    DROP DATABASE elearning;
                postgres    false            �            1259    116433    testresults    TABLE     �   CREATE TABLE public.testresults (
    testresultsid bigint NOT NULL,
    user_id integer NOT NULL,
    questions_id integer NOT NULL,
    testdate timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    score integer NOT NULL
);
    DROP TABLE public.testresults;
       public         heap    postgres    false            �            1259    116431    testresults_testresultsid_seq    SEQUENCE     �   CREATE SEQUENCE public.testresults_testresultsid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 4   DROP SEQUENCE public.testresults_testresultsid_seq;
       public          postgres    false    215            O           0    0    testresults_testresultsid_seq    SEQUENCE OWNED BY     _   ALTER SEQUENCE public.testresults_testresultsid_seq OWNED BY public.testresults.testresultsid;
          public          postgres    false    214            �
           2604    116436    testresults testresultsid    DEFAULT     �   ALTER TABLE ONLY public.testresults ALTER COLUMN testresultsid SET DEFAULT nextval('public.testresults_testresultsid_seq'::regclass);
 H   ALTER TABLE public.testresults ALTER COLUMN testresultsid DROP DEFAULT;
       public          postgres    false    214    215    215            H          0    116433    testresults 
   TABLE DATA           \   COPY public.testresults (testresultsid, user_id, questions_id, testdate, score) FROM stdin;
    public          postgres    false    215   �       P           0    0    testresults_testresultsid_seq    SEQUENCE SET     L   SELECT pg_catalog.setval('public.testresults_testresultsid_seq', 1, false);
          public          postgres    false    214            �
           2606    116439    testresults testresults_pkey 
   CONSTRAINT     e   ALTER TABLE ONLY public.testresults
    ADD CONSTRAINT testresults_pkey PRIMARY KEY (testresultsid);
 F   ALTER TABLE ONLY public.testresults DROP CONSTRAINT testresults_pkey;
       public            postgres    false    215            �
           2606    116445 )   testresults testresults_questions_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.testresults
    ADD CONSTRAINT testresults_questions_id_fkey FOREIGN KEY (questions_id) REFERENCES public.questions(questions_id);
 S   ALTER TABLE ONLY public.testresults DROP CONSTRAINT testresults_questions_id_fkey;
       public          postgres    false    215            �
           2606    116440 $   testresults testresults_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.testresults
    ADD CONSTRAINT testresults_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);
 N   ALTER TABLE ONLY public.testresults DROP CONSTRAINT testresults_user_id_fkey;
       public          postgres    false    215            H      x������ � �     