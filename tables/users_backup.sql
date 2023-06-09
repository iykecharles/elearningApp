PGDMP     +                    {        	   elearning    13beta3    13beta3     L           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            M           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            N           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            O           1262    107822 	   elearning    DATABASE     m   CREATE DATABASE elearning WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE = 'English_United States.1252';
    DROP DATABASE elearning;
                postgres    false            �            1259    107825    users    TABLE     �  CREATE TABLE public.users (
    user_id bigint NOT NULL,
    firstname character varying(50) NOT NULL,
    lastname character varying(50) NOT NULL,
    gender character varying(50) NOT NULL,
    email character varying(50) NOT NULL,
    age numeric(2,0) NOT NULL,
    usertype character varying(10) NOT NULL,
    username character varying(50) NOT NULL,
    hash character varying(100) NOT NULL,
    CONSTRAINT users_age_check CHECK (((age >= (0)::numeric) AND (age <= (75)::numeric))),
    CONSTRAINT users_usertype_check CHECK (((usertype)::text = ANY (ARRAY[('admin'::character varying)::text, ('student'::character varying)::text])))
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    107823    users_user_id_seq    SEQUENCE     z   CREATE SEQUENCE public.users_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.users_user_id_seq;
       public          postgres    false    201            P           0    0    users_user_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;
          public          postgres    false    200            �
           2604    107828    users user_id    DEFAULT     n   ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);
 <   ALTER TABLE public.users ALTER COLUMN user_id DROP DEFAULT;
       public          postgres    false    201    200    201            I          0    107825    users 
   TABLE DATA           k   COPY public.users (user_id, firstname, lastname, gender, email, age, usertype, username, hash) FROM stdin;
    public          postgres    false    201   �       Q           0    0    users_user_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.users_user_id_seq', 10, true);
          public          postgres    false    200            �
           2606    107834    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    201            �
           2606    107832    users users_pkey 
   CONSTRAINT     S   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    201            I     x�m�Oo�0�s���V�m�M�(��B�K�ږE#��g&$;x~�<�//U�(h虔%�IF�hSsrϨ���[K��z,s`��\rQ�!<Bd41F>��n�]��b�L>cHg2-c܍��J�$�=F�o��硎NB�@�hGs��r"�?��zB�=�v�����Yr~Н{jD4p\�c^�ջ7�󛍱Wj��t��jp��QOX�
p��dU�ZTO�S������4�KT̙����	M|kؖ�ʽ6�q� �[�4��Ђ�     